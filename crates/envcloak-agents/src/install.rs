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
//! keys; a file EnvCloak created and nothing else is in is removed, and a
//! file that is EnvCloak's whole only while it is exactly what EnvCloak
//! wrote. The MCP server is removed through Claude Code's own command
//! while it is the entry EnvCloak registered; one the person registered,
//! even with EnvCloak's very settings, is never claimed.
//!
//! With EnvCloak's plugin enabled in Claude Code, its hooks and MCP server
//! are not written again; the settings no plugin carries (the deny rule,
//! the sandbox entries) are. The hooks and MCP entries name EnvCloak by
//! its link on `PATH` ([`stable_exe`]).

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
use crate::writer::{
    Change, Created, Edit, Edited, FileRecord, Made, McpRecord, Outcome, Refusal, Stamp, Target,
    Undo, Writer, sha256_hex,
};

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
    /// EnvCloak's own registration of its MCP server in Claude Code taken
    /// out, if it made one: the enabled plugin carries the server.
    ClaudeMcpRemove,
    /// A change asked for and not made, and why: nothing is written.
    Withheld(Refusal),
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

/// The path the hooks and the MCP entries name EnvCloak by: the first
/// `envcloak` on `path` (a `PATH` value) that is the running program
/// (`exe`, its path resolved), as written there, else `exe` itself. A
/// package manager's link (`/opt/homebrew/bin/envcloak`) outlives an
/// upgrade, while the versioned file it points to (`.../Cellar/envcloak/
/// <version>/bin/envcloak`) does not, and a hook whose command is gone
/// fails open on both hosts (exit 127 is a non-blocking error).
pub fn stable_exe(exe: &Path, path: &std::ffi::OsStr) -> PathBuf {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(want) = std::fs::canonicalize(exe) else {
        return exe.to_path_buf();
    };
    path.as_bytes()
        .split(|&b| b == b':')
        .map(|d| Path::new(std::ffi::OsStr::from_bytes(d)))
        .filter(|d| d.is_absolute())
        .map(|d| d.join("envcloak"))
        .find(|c| std::fs::canonicalize(c).is_ok_and(|r| r == want))
        .unwrap_or(want)
}

fn strings(p: &[&str]) -> Vec<String> {
    p.iter().map(|s| (*s).to_owned()).collect()
}

/// Reads a small JSON file for a decision, if it is there and is JSON.
pub fn read_json(path: &Path) -> Option<Value> {
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
                Host::Codex => codex_plan(ctx, opts, d, &mut hp),
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
    // With EnvCloak's plugin enabled, its hooks and MCP server are there
    // already (installing them again would run each hook twice); the
    // settings no plugin carries (the deny rule, which also covers `@`
    // file mentions no hook sees, the sandbox entries) are still written.
    let plugin = read_json(&settings).is_some_and(|v| claude::plugin_enabled(&v));
    let macos = cfg!(target_os = "macos");
    let socket = macos.then(|| resolved(&ctx.socket));
    let mut additions: Vec<(Vec<String>, Value)> =
        claude::protections(socket.as_deref(), &ctx.data_dir)
            .into_iter()
            .map(|(p, v)| (strings(&p), v))
            .collect();
    if !plugin {
        additions.extend(
            claude::hooks_additions(&ctx.envcloak)
                .into_iter()
                .map(|(p, v)| (strings(&p), v)),
        );
    }
    let hooks = if plugin {
        String::new()
    } else {
        format!(
            "hooks (UserPromptSubmit; PreToolUse for {} and {}; SessionStart), ",
            claude::TOOL_MATCHER,
            claude::MCP_MATCHER
        )
    };
    hp.steps.push(Step {
        what: format!(
            "add {hooks}the deny rule {}, sandbox deny entries for EnvCloak's vault and \
             backups{}",
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
    if plugin {
        hp.notes.push(note(
            "plugin_enabled",
            "the EnvCloak plugin is enabled in Claude Code: its hooks and MCP server are already \
             there, so they are not written again, and the ones an earlier install wrote are \
             taken out (with both, each hook ran twice); the instruction block, the deny rule \
             and the sandbox settings, which the plugin does not carry, are written",
        ));
        hp.steps.push(Step {
            what: "remove the MCP server EnvCloak registered with `claude mcp add-json`, if it \
                   registered one: the plugin carries it"
                .to_owned(),
            path: l.claude_json().to_path_buf(),
            kind: StepKind::ClaudeMcpRemove,
        });
    } else {
        hp.steps.push(Step {
            what: "register EnvCloak's MCP server with `claude mcp add-json --scope user` \
                   (per-server timeout 60 s; no approval setting for any EnvCloak tool)"
                .to_owned(),
            path: l.claude_json().to_path_buf(),
            kind: StepKind::ClaudeMcp {
                exe: d.exe.clone(),
                entry: claude::mcp_entry(&ctx.envcloak),
            },
        });
    }
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

fn codex_plan(ctx: &Context<'_>, opts: &Options, d: &Detected, hp: &mut HostPlan) {
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
    // The allowance turns command networking on and relies on the proxy
    // settings to limit it to EnvCloak's socket, which M2-04 measured on
    // the pinned version only: another version gets none (Codex review).
    let qualified = crate::locations::socket_allowance_qualified(Host::Codex, &d.version);
    let socket = (!linux && opts.consent_sockets && qualified).then_some(ctx.socket.as_path());
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
    if !linux && opts.consent_sockets && !qualified {
        hp.steps.push(Step {
            what: "with your consent, command networking limited to EnvCloak's socket".to_owned(),
            path: l.codex_config(),
            kind: StepKind::Withheld(Refusal::new(
                "socket_allowance_unqualified",
                format!(
                    "Codex {} is not a version EnvCloak's socket allowance was measured on ({}): \
                     on another version the proxy settings that limit command networking to \
                     EnvCloak's socket may not hold, so the allowance is not written for it",
                    d.version,
                    crate::locations::SOCKET_ALLOWANCE_QUALIFIED
                        .iter()
                        .filter(|(h, _)| *h == Host::Codex.id())
                        .map(|(_, v)| *v)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )),
        });
    }
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

/// Settings EnvCloak may have written in an earlier run that `hp` no
/// longer writes, and what the report says when they were taken out, or
/// are still there.
struct Watched {
    path: PathBuf,
    edit: fn(&Edit) -> bool,
    removed: (&'static str, &'static str),
    left: (&'static str, &'static str),
}

/// An edit of Codex's socket allowance.
fn allowance_edit(e: &Edit) -> bool {
    matches!(e, Edit::TomlValue { path, .. } if codex::is_allowance_path(path))
}

/// An edit of Claude Code's hooks.
fn hook_edit(e: &Edit) -> bool {
    matches!(e, Edit::JsonElement { path, .. } if path.first().is_some_and(|k| k == "hooks"))
}

/// Whether EnvCloak's record of the file at `path` holds an edit `edit`
/// picks.
fn recorded(w: &Writer<'_>, path: &Path, edit: fn(&Edit) -> bool) -> bool {
    w.state
        .files
        .get(&crate::writer::key(path))
        .is_some_and(|r| r.edits.iter().any(edit))
}

/// What of an earlier run `hp` no longer writes (lesson L-09: the report
/// says what the files hold, not what this run alone did).
fn watched(ctx: &Context<'_>, hp: &HostPlan) -> Vec<Watched> {
    let writes = |pick: fn(&Edit) -> bool| {
        hp.steps.iter().any(|s| match &s.kind {
            StepKind::Toml { settings, .. } => settings.iter().any(|(p, v)| {
                pick(&Edit::TomlValue {
                    path: p.clone(),
                    value: v.clone(),
                    previous: None,
                    created: 0,
                })
            }),
            StepKind::Json { additions, .. } => additions.iter().any(|(p, v)| {
                pick(&Edit::JsonElement {
                    path: p.clone(),
                    value: v.clone(),
                    created: 0,
                })
            }),
            _ => false,
        })
    };
    if hp.steps.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    match hp.host {
        Host::Codex if !writes(allowance_edit) => out.push(Watched {
            path: ctx.locations.codex_config(),
            edit: allowance_edit,
            removed: (
                "socket_allowance_removed",
                "the socket allowance an earlier install wrote (network_access, the network \
                 proxy and its unix_sockets rule for EnvCloak's socket) is not in config.toml \
                 any more: this run does not write it (no --consent-sandbox-sockets, or a Codex \
                 version it was not measured on), and took out what was left of it, so the \
                 command networking it turned on is off and Codex's sandboxed shell cannot reach \
                 EnvCloak",
            ),
            left: (
                "socket_allowance_left",
                "the socket allowance an earlier install wrote is still in config.toml, since \
                 the change above was not made: command networking limited to EnvCloak's socket \
                 stays on until it is taken out. Run this again once the reason above is gone, \
                 or remove sandbox_workspace_write.network_access, [features.network_proxy] and \
                 its unix_sockets rule for EnvCloak's socket yourself",
            ),
        }),
        Host::ClaudeCode if !writes(hook_edit) => out.push(Watched {
            path: ctx.locations.claude_settings(),
            edit: hook_edit,
            removed: (
                "hooks_removed",
                "the hooks an earlier install wrote are not in settings.json any more: the \
                 enabled plugin carries them, so this run took out what was left of them (with \
                 both, each hook ran twice)",
            ),
            left: (
                "hooks_left",
                "the hooks an earlier install wrote are still in settings.json, beside the \
                 plugin's, since the change above was not made: each hook runs twice until they \
                 are taken out (run this again once the reason above is gone)",
            ),
        }),
        _ => {}
    }
    out
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
    /// Files under EnvCloak's temporary names that an earlier write left
    /// beside a config and that were not shown to be EnvCloak's, or could
    /// not be removed ([`Writer::leftovers_present`]): each may hold a copy
    /// of part of the config, so they are named, and the run is not
    /// complete while one is there (lesson L-08).
    pub leftovers: Vec<PathBuf>,
}

impl Report {
    /// Every change was made (or was there already), every host named
    /// with `--agent` was found, and no leftover is there.
    pub fn complete(&self) -> bool {
        let ok =
            |r: &StepResult| !matches!(r.outcome, Outcome::Refused(_) | Outcome::Partial { .. });
        self.hosts
            .iter()
            .all(|h| h.results.iter().all(ok) && (h.found.is_ok() || !h.requested))
            && self
                .project
                .as_ref()
                .is_none_or(|p| p.results.iter().all(ok))
            && self.leftovers.is_empty()
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

/// The edit of one step, given the file's contents and EnvCloak's record
/// of it.
fn edit_for(
    kind: &StepKind,
) -> impl FnMut(Option<&[u8]>, Option<&FileRecord>) -> Result<Edited, Refusal> + '_ {
    move |before: Option<&[u8]>, rec: Option<&FileRecord>| match kind {
        StepKind::Block => match blocks::insert(before.unwrap_or_default()) {
            Ok(blocks::Change::Unchanged) => Ok(None),
            Ok(blocks::Change::New(t)) => Ok(Some(Change::new(t.into_bytes(), vec![Edit::Block]))),
            Err(e) => Err(Refusal::new(e.name(), e.message())),
        },
        StepKind::Json { additions, .. } => {
            let mut doc = match before {
                Some(b) => Doc::parse(b).map_err(|e| Refusal::new(e.name(), e.message()))?,
                None => Doc::empty(),
            };
            // EnvCloak's earlier elements this run does not add go first,
            // while they are still there (the verifier's finding, in
            // JSON: the hooks the enabled plugin now carries, a socket or
            // a data directory that moved, were left beside the new ones).
            let stale: Vec<Edit> = rec
                .map(|r| {
                    r.edits
                        .iter()
                        .filter(|e| {
                            matches!(e, Edit::JsonElement { path, value, .. }
                                if !additions.iter().any(|(p, v)| p == path && v == value))
                        })
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            for e in stale.iter().rev() {
                if let Edit::JsonElement {
                    path,
                    value,
                    created,
                } = e
                {
                    let p: Vec<&str> = path.iter().map(String::as_str).collect();
                    doc.remove_from_array(&p, value, *created)
                        .map_err(|e| Refusal::new(e.name(), e.message()))?;
                }
            }
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
            if edits.is_empty() && stale.is_empty() {
                return Ok(None);
            }
            Ok(Some(Change {
                bytes: doc.text().as_bytes().to_vec(),
                added: edits,
                dropped: stale,
            }))
        }
        StepKind::Toml { settings, .. } => {
            let owned = rec.map(|r| r.edits.as_slice()).unwrap_or_default();
            codex::apply(before, settings, owned)
        }
        StepKind::OwnFile { content } => match (before, rec) {
            (Some(b), _) if b == content.as_bytes() => Ok(None),
            // An older version of EnvCloak's own file, as EnvCloak left it.
            (Some(b), Some(r)) if r.created && sha256_hex(b) == r.post_sha256 => Ok(Some(
                Change::new(content.as_bytes().to_vec(), vec![Edit::WholeFile]),
            )),
            (Some(_), Some(_)) => Err(modified()),
            (Some(_), None) => Err(Refusal::new(
                "conflict",
                "a file of this name is already there, and EnvCloak did not write it",
            )),
            (None, _) => Ok(Some(Change::new(
                content.as_bytes().to_vec(),
                vec![Edit::WholeFile],
            ))),
        },
        StepKind::ClaudeMcp { .. } | StepKind::ClaudeMcpRemove | StepKind::Withheld(_) => Ok(None),
    }
}

/// A file of EnvCloak's that someone else changed since.
fn modified() -> Refusal {
    Refusal::new(
        "modified",
        "the file changed since EnvCloak wrote it, so it was left as it is: remove it yourself \
         if nothing in it is yours",
    )
}

fn run_step(
    ctx: &Context<'_>,
    w: &mut Writer<'_>,
    step: &Step,
    t: Target,
    notes: &mut Vec<Note>,
) -> StepResult {
    let outcome = match &step.kind {
        StepKind::ClaudeMcp { exe, entry } => register_claude_mcp(ctx, w, exe, entry, notes),
        StepKind::ClaudeMcpRemove => {
            let key = mcp_key(ctx.locations.claude_json());
            if w.state.mcp.contains_key(&key) || w.state.mcp_intent.contains_key(&key) {
                unregister_claude_mcp(ctx, w, &key)
            } else {
                Outcome::Unchanged
            }
        }
        StepKind::Withheld(r) => Outcome::Refused(r.clone()),
        kind => {
            let mut edit = edit_for(kind);
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
        leftovers: Vec::new(),
    };
    // What earlier runs left under temporary names goes first.
    w.sweep_all();
    for hp in &plan.hosts {
        let mut results = Vec::new();
        let mut notes = hp.notes.clone();
        // What EnvCloak wrote before that this plan no longer writes (the
        // socket allowance, the hooks the plugin carries): whether it was
        // there before the steps, to say after them what became of it.
        let watched = watched(ctx, hp);
        let was: Vec<bool> = watched
            .iter()
            .map(|wt| recorded(w, &wt.path, wt.edit))
            .collect();
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
            results.push(run_step(ctx, w, step, t, &mut notes));
        }
        for (wt, was) in watched.iter().zip(was) {
            match (was, recorded(w, &wt.path, wt.edit)) {
                (_, true) => notes.push(note(wt.left.0, wt.left.1)),
                (true, false) => notes.push(note(wt.removed.0, wt.removed.1)),
                (false, false) => {}
            }
        }
        report.hosts.push(HostReport {
            host: hp.host,
            requested: hp.requested,
            found: hp.found.clone(),
            results,
            notes,
        });
    }
    if let Some(pp) = &plan.project {
        let scope = pp.dir.to_string_lossy().into_owned();
        let results = pp
            .steps
            .iter()
            .map(|step| {
                let t = target(&step.path, "project", scope.clone(), false, "the agent");
                run_step(ctx, w, step, t, &mut Vec::new())
            })
            .collect();
        report.project = Some(ProjectReport {
            dir: pp.dir.clone(),
            results,
        });
    }
    w.sweep_all();
    report.leftovers = w.leftovers_present();
    report
}

/// What a `.claude.json` holds: the user-scope MCP entry named
/// `envcloak` (`None` for none), and the file (`None` when there is none).
struct ClaudeJson {
    entry: Option<Value>,
    file: Option<ClaudeFile>,
}

/// A `.claude.json` as read: its bytes and stamp.
struct ClaudeFile {
    bytes: Vec<u8>,
    stamp: envcloak_scan::FileStamp,
}

/// The key the state keeps an MCP registration in the file at `path`
/// under ([`crate::writer::State::mcp`]): its path with its directories
/// resolved, so the same file is one key however it is reached.
pub fn mcp_key(path: &Path) -> String {
    let resolved = match (path.parent(), path.file_name()) {
        (Some(d), Some(n)) => {
            std::fs::canonicalize(d).map_or_else(|_| path.to_path_buf(), |d| d.join(n))
        }
        _ => path.to_path_buf(),
    };
    crate::writer::key(&resolved)
}

/// The user-scope MCP entry in the `.claude.json` at `path`, read beneath
/// its directory.
fn claude_registered(path: &Path) -> Result<ClaudeJson, Refusal> {
    let none = || ClaudeJson {
        entry: None,
        file: None,
    };
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Ok(none());
    };
    let Ok(root) = open_root(dir) else {
        return Ok(none());
    };
    match read_plain(&root, Path::new(name), 64 * 1024 * 1024) {
        // Claude Code rewrites the file through its own command, but the
        // writer's rule holds for it all the same (Codex review): a file
        // with another hard link is reported, and EnvCloak runs no
        // command that would change it. (A symlink is refused by the
        // read.)
        Ok((_, stamp)) if stamp.nlink > 1 => Err(Refusal::new(
            "hard_linked",
            "it has another hard link, which would keep its old contents: reported, never \
             changed",
        )),
        Ok((bytes, stamp)) => Ok(ClaudeJson {
            entry: claude::registered(&bytes)?,
            file: Some(ClaudeFile { bytes, stamp }),
        }),
        Err(e) if e.kind == ScanErrorKind::NotFound => Ok(none()),
        Err(e) => Err(Refusal::new(e.kind.token(), e.kind.message())),
    }
}

/// Whether the `.claude.json` at `path` holds a user-scope MCP server
/// named `envcloak` (anyone's), read as the installer reads it.
pub fn claude_json_has_server(path: &Path) -> bool {
    claude_registered(path).is_ok_and(|c| c.entry.is_some())
}

fn register_claude_mcp(
    ctx: &Context<'_>,
    w: &mut Writer<'_>,
    exe: &Path,
    entry: &Value,
    notes: &mut Vec<Note>,
) -> Outcome {
    match try_register(ctx, w, exe, entry, notes) {
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

/// Settles an MCP registration saved and not confirmed (a run stopped
/// while `claude mcp` ran) in the file keyed `key`: EnvCloak's when the
/// entry it was registering is there, else forgotten.
fn settle_mcp(w: &mut Writer<'_>, key: &str, current: Option<&Value>) {
    if let Some(intent) = w.state.mcp_intent.remove(key) {
        if current == Some(&intent.entry) {
            w.state.mcp.insert(key.to_owned(), intent);
        }
    }
}

/// `CLAUDE_CONFIG_DIR` as the person's environment gives it, when it is
/// one the catalog reads (absolute: [`Locations`]).
fn config_dir(ctx: &Context<'_>) -> Option<String> {
    (ctx.env)("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .map(|p| p.to_string_lossy().into_owned())
}

fn try_register(
    ctx: &Context<'_>,
    w: &mut Writer<'_>,
    exe: &Path,
    entry: &Value,
    notes: &mut Vec<Note>,
) -> Result<Outcome, Refusal> {
    let host = Host::ClaudeCode.id();
    let path = ctx.locations.claude_json().to_path_buf();
    let key = mcp_key(&path);
    let now = claude_registered(&path)?;
    settle_mcp(w, &key, now.entry.as_ref());
    let mine = w.state.mcp.get(&key).cloned();
    let ours = now.entry.is_some() && mine.as_ref().map(|r| &r.entry) == now.entry.as_ref();
    if now.entry.as_ref() == Some(entry) {
        if !ours {
            // The person's own entry, equal to EnvCloak's: left theirs, and
            // uninstall leaves it (Codex review).
            notes.push(note(
                "mcp_server_yours",
                "an MCP server named `envcloak` with EnvCloak's settings is already registered \
                 in Claude Code, and EnvCloak did not register it: it is left as yours, and \
                 `agents uninstall` leaves it",
            ));
        }
        return Ok(Outcome::Unchanged);
    }
    if now.entry.is_some() && !ours {
        return Err(Refusal::new(
            "conflict",
            "an MCP server named `envcloak` is already registered in Claude Code, and EnvCloak \
             did not register it; remove or rename it first",
        ));
    }
    // Claude Code changes its own file; EnvCloak backs it up first.
    let backup = match &now.file {
        Some(f) => Some(w.backups.back_up(&path, &f.bytes, f.stamp.mode)?),
        None => None,
    };
    let unmade = |w: &mut Writer<'_>| {
        if let (Some(id), Some(f)) = (&backup, &now.file) {
            let _ = w.backups.record(id, &f.bytes);
        }
    };
    // The file holds only what EnvCloak's registrations made: there was
    // none, or it is exactly what the last one left.
    let fresh = match (&now.file, mine.as_ref().and_then(|r| r.created.as_ref())) {
        (None, _) => true,
        (Some(f), Some(c)) => sha256_hex(&f.bytes) == c.sha256,
        (Some(_), None) => false,
    };
    // Saved before the host's command runs: a run stopped after it still
    // owns what it registered.
    w.state.mcp_intent.insert(
        key.clone(),
        McpRecord {
            host: host.to_owned(),
            entry: entry.clone(),
            config_dir: config_dir(ctx),
            created: None,
        },
    );
    if let Err(e) = w.journal.save(w.state) {
        w.state.mcp_intent.remove(&key);
        unmade(w);
        return Err(e);
    }
    let ran = (|| {
        if now.entry.is_some() {
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
        claude::run(exe, &["mcp", "get", claude::SERVER], ctx.env)
    })();
    let after = claude_registered(&path)?;
    // Whatever the commands answered, the file says what is registered.
    settle_mcp(w, &key, after.entry.as_ref());
    if after.entry.as_ref() != Some(entry) {
        let _ = w.journal.save(w.state);
        if after.entry == now.entry {
            unmade(w);
        } else if let (Some(id), Some(f)) = (&backup, &after.file) {
            let _ = w.backups.record(id, &f.bytes);
        }
        return Err(ran.err().unwrap_or_else(|| {
            Refusal::new(
                "host_cli_failed",
                "after `claude mcp add-json`, `claude mcp get` does not show EnvCloak's server as \
                 written",
            )
        }));
    }
    // What the file holds now, when it holds nothing but what EnvCloak's
    // registrations made: uninstall removes it while it is still so.
    if let Some(r) = w.state.mcp.get_mut(&key) {
        r.created = match &after.file {
            Some(f) if fresh => Some(Created {
                sha256: sha256_hex(&f.bytes),
                stamp: Some(Stamp::from(f.stamp)),
            }),
            _ => None,
        };
    }
    let mut failed = match ran {
        Ok(out) if out.status.success() => None,
        Ok(_) => Some(cli_failed("get")),
        Err(e) => Some(e),
    };
    if let Err(e) = w.journal.save(w.state) {
        failed.get_or_insert(e);
    }
    if let (Some(id), Some(f)) = (&backup, &after.file) {
        if let Err(e) = w.backups.record(id, &f.bytes) {
            failed.get_or_insert(e);
        }
    }
    let made = if now.file.is_none() {
        Made::Created
    } else {
        Made::Changed
    };
    Ok(match failed {
        Some(failed) => Outcome::Partial {
            made,
            backup,
            failed,
        },
        None => Outcome::Changed {
            created: now.file.is_none(),
            backup,
        },
    })
}

/// The path a registration keyed `key` is shown by: the catalog's own
/// spelling when it is the file `CLAUDE_CONFIG_DIR` names now (its
/// directories unresolved, as a person knows them), else the key's.
pub fn registration_path(ctx: &Context<'_>, key: &str) -> PathBuf {
    let here = ctx.locations.claude_json();
    if mcp_key(here) == key {
        here.to_path_buf()
    } else {
        PathBuf::from(key)
    }
}

/// The keys of the MCP registrations EnvCloak holds for Claude Code,
/// confirmed or not.
pub fn claude_registrations(state: &crate::writer::State) -> Vec<String> {
    let host = Host::ClaudeCode.id();
    let mut keys: Vec<String> = state
        .mcp
        .iter()
        .chain(state.mcp_intent.iter())
        .filter(|(_, r)| r.host == host)
        .map(|(k, _)| k.clone())
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Takes EnvCloak's MCP server out of the `.claude.json` keyed `key`,
/// while it is the entry EnvCloak registered there: with `claude mcp
/// remove`, pointed at that file (`CLAUDE_CONFIG_DIR` as it was when the
/// entry was registered, or with none, `HOME` the file's directory), or,
/// when EnvCloak's registration created the file and it is still exactly
/// as that left it, by removing the file, which holds nothing else.
fn unregister_claude_mcp(ctx: &Context<'_>, w: &mut Writer<'_>, key: &str) -> Outcome {
    let path = PathBuf::from(key);
    let outcome = (|| -> Result<Outcome, Refusal> {
        let now = claude_registered(&path)?;
        settle_mcp(w, key, now.entry.as_ref());
        let Some(rec) = w.state.mcp.get(key).cloned() else {
            let _ = w.journal.save(w.state);
            return Ok(Outcome::Unchanged);
        };
        let (Some(file), true) = (&now.file, now.entry.as_ref() == Some(&rec.entry)) else {
            // Gone, or changed since: not EnvCloak's to remove.
            w.state.mcp.remove(key);
            let _ = w.journal.save(w.state);
            return Ok(Outcome::Unchanged);
        };
        if rec
            .created
            .as_ref()
            .is_some_and(|c| c.sha256 == sha256_hex(&file.bytes))
        {
            return remove_created(w, key, &path, file, &rec);
        }
        let exe = detect::detect(Host::ClaudeCode, &ctx.path, ctx.env)
            .map_err(|e| Refusal::new(e.name(), e.message()))?
            .exe;
        let backup = Some(w.backups.back_up(&path, &file.bytes, file.stamp.mode)?);
        let env = |k: &str| match (k, &rec.config_dir) {
            ("CLAUDE_CONFIG_DIR", d) => d.as_ref().map(OsString::from),
            ("HOME", None) => path.parent().map(|p| p.as_os_str().to_owned()),
            _ => (ctx.env)(k),
        };
        let ran = claude::run(
            &exe,
            &["mcp", "remove", "--scope", "user", claude::SERVER],
            &env,
        );
        let after = claude_registered(&path)?;
        if after.entry.is_some() {
            if let (Some(id), Some(f)) = (&backup, &after.file) {
                let _ = w.backups.record(id, &f.bytes);
            }
            return Err(ran.err().unwrap_or_else(|| cli_failed("remove")));
        }
        w.state.mcp.remove(key);
        let mut failed = match ran {
            Ok(out) if out.status.success() => None,
            Ok(_) => Some(cli_failed("remove")),
            Err(e) => Some(e),
        };
        if let Err(e) = w.journal.save(w.state) {
            failed.get_or_insert(e);
        }
        if let (Some(id), Some(f)) = (&backup, &after.file) {
            if let Err(e) = w.backups.record(id, &f.bytes) {
                failed.get_or_insert(e);
            }
        }
        Ok(match failed {
            Some(failed) => Outcome::Partial {
                made: Made::Removed,
                backup,
                failed,
            },
            None => Outcome::Removed { backup },
        })
    })();
    outcome.unwrap_or_else(Outcome::Refused)
}

/// Removes the `.claude.json` at `path` that EnvCloak's registration
/// created and that is still exactly as it left it (`rec.created`), after
/// a backup: D-16's rules as for any host file (not open elsewhere; the 2
/// minutes, unless its stamp is still the one the registration left).
fn remove_created(
    w: &mut Writer<'_>,
    key: &str,
    path: &Path,
    file: &ClaudeFile,
    rec: &McpRecord,
) -> Result<Outcome, Refusal> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(Refusal::new("invalid_path", "not a file's path"));
    };
    let root = open_root(dir)
        .map_err(|_| Refusal::new("unreadable", "its directory could not be opened"))?;
    let own = rec
        .created
        .as_ref()
        .is_some_and(|c| c.stamp == Some(Stamp::from(file.stamp)));
    let at = if own {
        let mtime = std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(u64::try_from(file.stamp.mtime).unwrap_or(0));
        w.now.max(mtime + envcloak_scan::MIN_AGE)
    } else {
        w.now
    };
    let id = w.backups.back_up(path, &file.bytes, file.stamp.mode)?;
    let gone = envcloak_scan::remove_checked_at(&root, Path::new(name), &file.stamp, at);
    let present = !matches!(
        read_plain(&root, Path::new(name), crate::writer::MAX_FILE),
        Err(e) if e.kind == ScanErrorKind::NotFound
    );
    let mut failed = match gone {
        Ok(()) => None,
        Err(e) if present => {
            let _ = w.backups.record(&id, &file.bytes);
            return Err(Refusal::new(e.kind.token(), e.kind.message()));
        }
        Err(e) => Some(Refusal::new(e.kind.token(), e.kind.message())),
    };
    w.state.mcp.remove(key);
    if let Err(e) = w.journal.save(w.state) {
        failed.get_or_insert(e);
    }
    if let Err(e) = w.backups.record(&id, b"") {
        failed.get_or_insert(e);
    }
    Ok(match failed {
        Some(failed) => Outcome::Partial {
            made: Made::Removed,
            backup: Some(id),
            failed,
        },
        None => Outcome::Removed { backup: Some(id) },
    })
}

/// Takes EnvCloak's edits out of a file changed since its last write.
///
/// # Errors
/// When the file cannot be read in its format, or it is EnvCloak's whole
/// file and changed since EnvCloak wrote it (a file EnvCloak wrote whole is
/// removed only while it is exactly what EnvCloak wrote, which the writer
/// checks first): it is left as it is, and reported.
pub fn structural(current: &[u8], edits: &[Edit], created: bool) -> Result<Undo, Refusal> {
    if edits.contains(&Edit::WholeFile) {
        return Err(modified());
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
        leftovers: Vec::new(),
    };
    w.sweep_all();
    let undo_files = |w: &mut Writer<'_>, host: &'static str, scope: &str, name: &'static str| {
        let paths: Vec<(String, bool)> = w
            .state
            .files
            .iter()
            .filter(|(_, r)| r.host == host && r.scope == scope)
            .map(|(p, r)| (p.clone(), r.host_owned))
            .collect();
        paths
            .into_iter()
            .map(|(p, host_owned)| {
                let path = PathBuf::from(&p);
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
                // Every file EnvCloak registered its server in, wherever
                // `CLAUDE_CONFIG_DIR` points now.
                for key in claude_registrations(w.state) {
                    let outcome = unregister_claude_mcp(ctx, w, &key);
                    results.push(StepResult {
                        what: "remove EnvCloak's MCP server with `claude mcp remove --scope user`"
                            .to_owned(),
                        path: registration_path(ctx, &key),
                        outcome,
                    });
                }
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
    w.sweep_all();
    report.leftovers = w.leftovers_present();
    report
}

/// The SHA-256 of a file's bytes as the state keeps them, for tests and
/// reports.
pub fn digest(b: &[u8]) -> String {
    sha256_hex(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The state as saved; `fail` refuses the saves whose numbers (from
    /// 1) it holds.
    #[derive(Default)]
    struct Saved {
        fail: Vec<usize>,
        count: usize,
    }

    impl crate::writer::Journal for Saved {
        fn save(&mut self, _: &crate::writer::State) -> Result<(), Refusal> {
            self.count += 1;
            if self.fail.contains(&self.count) {
                return Err(Refusal::new("state_unwritable", "refused for the test"));
            }
            Ok(())
        }
    }

    struct NoBackups;

    impl crate::writer::Backups for NoBackups {
        fn back_up(&mut self, _: &Path, _: &[u8], _: u32) -> Result<String, Refusal> {
            Ok("B".to_owned())
        }
        fn record(&mut self, _: &str, _: &[u8]) -> Result<(), Refusal> {
            Ok(())
        }
    }

    /// Claude Code 2.1.280 as the installer runs it: `--version`, and
    /// `mcp add-json --scope user`, `get` and `remove --scope user` on
    /// `$HOME/.claude.json`, rewritten whole (the CLI tests' stand-in).
    const FAKE_CLAUDE: &str = r#"
import json, os, sys
args = sys.argv[1:]
if args == ["--version"]:
    print("2.1.280 (Claude Code)")
    sys.exit(0)
path = os.path.join(os.environ["HOME"], ".claude.json")
def load():
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
def save(v):
    with open(path + ".tmp", "w") as f:
        json.dump(v, f)
    os.rename(path + ".tmp", path)
if args[:4] == ["mcp", "add-json", "--scope", "user"]:
    v = load()
    v.setdefault("mcpServers", {})[args[4]] = json.loads(args[5])
    save(v)
    sys.exit(0)
if args[:4] == ["mcp", "remove", "--scope", "user"]:
    v = load()
    del v["mcpServers"][args[4]]
    save(v)
    sys.exit(0)
if args[:2] == ["mcp", "get"]:
    sys.exit(0 if args[2] in load().get("mcpServers", {}) else 1)
sys.exit(2)
"#;

    /// The verifier's class (a state save failing after a change, never
    /// tested on every path): after `claude mcp add-json`, and after
    /// `claude mcp remove`, a failing save is reported with the server as
    /// registered or removed, never as a success.
    ///
    /// Mutation checked: the final save's failure ignored in
    /// `try_register` and in `unregister_claude_mcp` (`let _ =`): the
    /// outcomes are `Changed` and `Removed`, and this fails.
    #[test]
    fn a_state_save_failing_after_claude_codes_command_says_so() {
        let Some(python) = std::env::var_os("PATH").and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("python3"))
                .find(|c| c.is_file())
        }) else {
            eprintln!("skipped: no python3 on PATH for the stand-in claude");
            return;
        };
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let home = std::fs::canonicalize(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        let bin = home.join("bin");
        std::fs::create_dir(&bin).unwrap_or_else(|e| panic!("{e}"));
        let claude = bin.join("claude");
        std::fs::write(&claude, format!("#!{}\n{FAKE_CLAUDE}", python.display()))
            .unwrap_or_else(|e| panic!("{e}"));
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        let home_os = home.clone().into_os_string();
        let env = move |k: &str| match k {
            "HOME" => Some(home_os.clone()),
            "PATH" => Some(OsString::from("/usr/bin:/bin")),
            _ => None,
        };
        let ctx = Context {
            locations: Locations::new(&env).unwrap_or_else(|_| panic!("no home")),
            envcloak: PathBuf::from("/b/envcloak"),
            data_dir: home.join("data"),
            socket: home.join("s.sock"),
            path: bin.clone().into_os_string(),
            env: &env,
        };
        // A file Claude Code wrote first, so `claude mcp remove` takes the
        // entry out (a file the registration created is removed whole).
        std::fs::write(home.join(".claude.json"), b"{\"numStartups\": 1}")
            .unwrap_or_else(|e| panic!("{e}"));
        let entry = claude::mcp_entry(Path::new("/b/envcloak"));
        let mut state = crate::writer::State::default();
        let mut backups = NoBackups;
        // The intent's save, then the save after the command: the second
        // fails.
        let mut saved = Saved {
            fail: vec![2],
            ..Saved::default()
        };
        let mut w = Writer {
            state: &mut state,
            journal: &mut saved,
            backups: &mut backups,
            now: std::time::SystemTime::now(),
        };
        let o = register_claude_mcp(&ctx, &mut w, &claude, &entry, &mut Vec::new());
        assert!(
            matches!(&o, Outcome::Partial { made: Made::Changed, failed, .. } if failed.name == "state_unwritable"),
            "{o:?}"
        );
        let key = mcp_key(&home.join(".claude.json"));
        assert_eq!(w.state.mcp.get(&key).map(|r| &r.entry), Some(&entry));
        // The only save after `claude mcp remove` fails.
        let mut saved = Saved {
            fail: vec![1],
            ..Saved::default()
        };
        let mut w = Writer {
            state: &mut state,
            journal: &mut saved,
            backups: &mut backups,
            now: std::time::SystemTime::now(),
        };
        let r = unregister_claude_mcp(&ctx, &mut w, &key);
        assert!(
            matches!(&r, Outcome::Partial { made: Made::Removed, failed, .. } if failed.name == "state_unwritable"),
            "{r:?}"
        );
        let left = std::fs::read(home.join(".claude.json")).unwrap_or_default();
        assert!(claude::registered(&left).is_ok_and(|e| e.is_none()));
    }

    /// Lesson L-09 for the hooks' own command: a versioned install (a
    /// package manager's `Cellar/<version>/bin/envcloak`) is named by the
    /// link on `PATH` that outlives an upgrade, never a link to another
    /// program, and a path with none is named as it is.
    ///
    /// Mutation checked: `stable_exe` returning the resolved path (the
    /// previous `current_exe().canonicalize()`): the hooks name the
    /// versioned file and this fails.
    #[test]
    fn the_hooks_name_envcloak_by_its_link_on_path() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let real = std::fs::canonicalize(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        let cellar = real.join("Cellar/envcloak/1.2.3/bin");
        let bin = real.join("bin");
        let other = real.join("other");
        for d in [&cellar, &bin, &other] {
            std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
        }
        let exe = cellar.join("envcloak");
        std::fs::write(&exe, b"x").unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(other.join("envcloak"), b"y").unwrap_or_else(|e| panic!("{e}"));
        std::os::unix::fs::symlink(&exe, bin.join("envcloak")).unwrap_or_else(|e| panic!("{e}"));
        let path = format!("relative:{}:{}", other.display(), bin.display());
        assert_eq!(
            stable_exe(&exe, std::ffi::OsStr::new(&path)),
            bin.join("envcloak")
        );
        let none = other.display().to_string();
        assert_eq!(stable_exe(&exe, std::ffi::OsStr::new(&none)), exe);
    }
}
