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
//! wrote. Claude Code's `.claude.json` is changed through the same writer
//! (its MCP server entry, `mcpServers.envcloak`): the entry is taken out
//! while it is the one EnvCloak added; one the person registered, even
//! with EnvCloak's very settings, is never claimed.
//!
//! With EnvCloak's plugin enabled in Claude Code, its hooks and MCP server
//! are not written again; the settings no plugin carries (the deny rule,
//! the sandbox entries) are. The hooks and MCP entries name EnvCloak by
//! its link on `PATH` ([`stable_exe`]).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use envcloak_scan::{open_root, read_plain};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::blocks;
use crate::detect::{self, DetectError, Detected};
use crate::hook::Host;
use crate::hosts::{claude, codex};
use crate::jsonedit::Doc;
use crate::locations::Locations;
use crate::writer::{
    Change, Edit, Edited, FileRecord, Outcome, Refusal, Target, Undo, Writer, sha256_hex,
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

/// What of Codex's instruction budget a block in a file Codex reads may
/// use (Codex review: a block appended past it is never read): the
/// budget, and the files Codex reads before this one, whose sizes count
/// against it when the block is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexBudget {
    pub limit: usize,
    pub before: Vec<PathBuf>,
    /// The `AGENTS.override.md` that, once there, Codex reads instead of
    /// this file: looked for again when the block is written (lesson
    /// L-09), not only when the plan was made.
    pub shadowed_by: Option<PathBuf>,
}

impl CodexBudget {
    /// What is left of the budget for this file now: each file read
    /// before it costs its size and the blank line Codex joins them with.
    /// One whose size cannot be read (other than gone) takes it all: the
    /// block is then refused rather than written where it may not be read.
    fn left(&self) -> usize {
        let mut used = 0usize;
        for p in &self.before {
            match std::fs::metadata(p) {
                Ok(m) => {
                    used = used.saturating_add(
                        usize::try_from(m.len())
                            .unwrap_or(usize::MAX)
                            .saturating_add(2),
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return 0,
            }
        }
        self.limit.saturating_sub(used)
    }

    /// Refused when the override that shadows this file is there now.
    fn shadowed(&self) -> Result<(), Refusal> {
        match &self.shadowed_by {
            Some(o) if std::fs::symlink_metadata(o).is_ok() => Err(Refusal::new(
                "override_file",
                "an AGENTS.override.md beside it is what Codex reads instead, so the block would \
                 not be read there: it was not written",
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum StepKind {
    /// EnvCloak's instruction block in a Markdown file; with `codex`, one
    /// Codex reads, where the block must end within its budget.
    Block { codex: Option<CodexBudget> },
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
    /// EnvCloak's MCP server entry in Claude Code's `.claude.json`
    /// (`mcpServers.envcloak`), added through the writer; with `None`,
    /// EnvCloak's own earlier entry taken out, if it added one: the
    /// enabled plugin carries the server.
    ClaudeMcp { entry: Option<Value> },
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
        project: opts
            .project
            .as_ref()
            .map(|d| project_plan(d, &hosts, &ctx.locations)),
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
                Host::ClaudeCode => claude_plan(ctx, &mut hp),
                Host::Codex => codex_plan(ctx, opts, d, &mut hp),
            }
        }
        out.hosts.push(hp);
    }
    out
}

fn claude_plan(ctx: &Context<'_>, hp: &mut HostPlan) {
    let l = &ctx.locations;
    hp.steps.push(Step {
        what: "add EnvCloak's instruction block".to_owned(),
        path: l.claude_instructions(),
        kind: StepKind::Block { codex: None },
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
             there, so they are not written (with both, each hook would run twice), and those an \
             earlier install wrote are taken out, as the lines here say; the instruction block, \
             the deny rule and the sandbox settings, which the plugin does not carry, are \
             written",
        ));
        hp.steps.push(Step {
            what: "remove the MCP server entry EnvCloak added, if it added one: the plugin \
                   carries it"
                .to_owned(),
            path: l.claude_json().to_path_buf(),
            kind: StepKind::ClaudeMcp { entry: None },
        });
    } else {
        hp.steps.push(Step {
            what: "add EnvCloak's MCP server (user scope, mcpServers.envcloak; per-server \
                   timeout 60 s; no approval setting for any EnvCloak tool)"
                .to_owned(),
            path: l.claude_json().to_path_buf(),
            kind: StepKind::ClaudeMcp {
                entry: Some(claude::mcp_entry(&ctx.envcloak)),
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
            "~/.codex/AGENTS.override.md exists and Codex reads it instead of AGENTS.md, so this \
             run writes no instruction block for Codex (one in AGENTS.md is not read while the \
             override is there): add the block to the override yourself, or remove the override \
             and run this again",
        ));
    } else {
        hp.steps.push(Step {
            what: "add EnvCloak's instruction block".to_owned(),
            path: l.codex_instructions(),
            kind: StepKind::Block {
                codex: Some(CodexBudget {
                    limit: codex_doc_budget(&[l.codex_config()]).0,
                    before: Vec::new(),
                    shadowed_by: Some(l.codex_instructions_override()),
                }),
            },
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

/// Codex's instruction budget and fallback file names, as the
/// `config.toml` files at `configs` give them: the smallest budget of
/// [`codex::DOC_BUDGET`] and theirs (a larger one is not counted on), and
/// their fallback names, the first file's first.
fn codex_doc_budget(configs: &[PathBuf]) -> (usize, Vec<String>) {
    let mut limit = codex::DOC_BUDGET;
    let mut fallbacks: Vec<String> = Vec::new();
    for c in configs {
        let Some(bytes) = c.parent().and_then(|d| {
            let root = open_root(d).ok()?;
            read_plain(&root, Path::new(c.file_name()?), crate::writer::MAX_FILE).ok()
        }) else {
            continue;
        };
        let (max, names) = codex::doc_settings(&Zeroizing::new(bytes.0));
        if let Some(m) = max {
            limit = limit.min(m);
        }
        for n in names {
            if !fallbacks.contains(&n) {
                fallbacks.push(n);
            }
        }
    }
    (limit, fallbacks)
}

/// The instruction file Codex reads in `dir`: at most one, the first of
/// `AGENTS.override.md`, `AGENTS.md` and the fallback names that is there
/// (Map C section 2.2).
fn codex_file_in(dir: &Path, fallbacks: &[String]) -> Option<PathBuf> {
    ["AGENTS.override.md", "AGENTS.md"]
        .into_iter()
        .map(str::to_owned)
        .chain(fallbacks.iter().cloned())
        .map(|n| dir.join(n))
        .find(|p| std::fs::symlink_metadata(p).is_ok())
}

/// The files Codex reads before `dir`'s: one in each directory from the
/// project root (the nearest directory above `dir` holding `.git`) down
/// to `dir`'s parent, root first. None when no directory above holds
/// `.git` (Codex then reads the working directory's only).
fn codex_files_above(dir: &Path, fallbacks: &[String]) -> Vec<PathBuf> {
    let above: Vec<&Path> = dir.ancestors().skip(1).collect();
    if std::fs::symlink_metadata(dir.join(".git")).is_ok() {
        return Vec::new();
    }
    let Some(root) = above
        .iter()
        .position(|a| std::fs::symlink_metadata(a.join(".git")).is_ok())
    else {
        return Vec::new();
    };
    above[..=root]
        .iter()
        .rev()
        .filter_map(|a| codex_file_in(a, fallbacks))
        .collect()
}

/// A Claude Code instruction file in a directory above `dir` (other than
/// the person's own `~/.claude/CLAUDE.md`, `user`): while one is there,
/// Claude Code does not read `AGENTS.md` (Map C section 2.1).
fn claude_file_above(dir: &Path, user: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .skip(1)
        .flat_map(|a| {
            ["CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md"]
                .into_iter()
                .map(move |n| a.join(n))
        })
        .find(|p| p != user && std::fs::symlink_metadata(p).is_ok())
}

/// The project scope's steps for `hosts` (Map C section 6; Codex review:
/// one destination for every host missed Codex beside a lone `CLAUDE.md`,
/// and wrote an `AGENTS.md` an `AGENTS.override.md` shadows). Each host's
/// file is chosen by that host's own precedence, in `dir`:
///
/// - Codex reads one file: `AGENTS.override.md`, else `AGENTS.md`, else
///   the first of `project_doc_fallback_filenames` there; with none, a new
///   `AGENTS.md`. An override is never written: the note says the block
///   is not there for Codex. The block ends within Codex's budget, after
///   the files Codex reads above `dir` up to the project root.
/// - Claude Code reads `CLAUDE.md`, `.claude/CLAUDE.md` or
///   `CLAUDE.local.md`, the first there; with none, `AGENTS.md` (from
///   2.1.277, while no such file is above `dir` either: a note names one
///   that is). A `CLAUDE.md` or `CLAUDE.local.md` is never created beside
///   a lone `AGENTS.md`.
///
/// One file both read gets one step.
pub fn project_plan(dir: &Path, hosts: &[Host], l: &Locations) -> ProjectPlan {
    let present = |n: &str| std::fs::symlink_metadata(dir.join(n)).is_ok();
    let mut notes = Vec::new();
    let mut steps: Vec<Step> = Vec::new();
    let mut add = |path: PathBuf, codex: Option<CodexBudget>, who: &str| {
        if let Some(s) = steps.iter_mut().find(|s| s.path == path) {
            s.what = "add EnvCloak's instruction block (read by Claude Code and Codex)".to_owned();
            if let (StepKind::Block { codex: c @ None }, Some(b)) = (&mut s.kind, codex) {
                *c = Some(b);
            }
            return;
        }
        steps.push(Step {
            what: format!("add EnvCloak's instruction block (read by {who})"),
            path,
            kind: StepKind::Block { codex },
        });
    };
    if hosts.contains(&Host::ClaudeCode) {
        match ["CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md"]
            .into_iter()
            .find(|n| present(n))
        {
            Some(n) => add(dir.join(n), None, "Claude Code"),
            None => match claude_file_above(dir, &l.claude_instructions()) {
                Some(above) => notes.push(note(
                    "claude_reads_above",
                    format!(
                        "Claude Code reads {} here, and so not this project's AGENTS.md: no \
                         project block is written for it (the block in ~/.claude/CLAUDE.md, \
                         which `agents install` writes, still reaches it)",
                        above.display()
                    ),
                )),
                None => {
                    add(dir.join("AGENTS.md"), None, "Claude Code");
                    notes.push(note(
                        "claude_reads_agents_md",
                        "Claude Code reads the block in this project's AGENTS.md from version \
                         2.1.277, while no CLAUDE.md, .claude/CLAUDE.md or CLAUDE.local.md is in \
                         the project or above it",
                    ));
                }
            },
        }
    }
    if hosts.contains(&Host::Codex) {
        let (limit, fallbacks) =
            codex_doc_budget(&[l.codex_config(), dir.join(".codex").join("config.toml")]);
        if present("AGENTS.override.md") {
            notes.push(note(
                "project_override_file",
                "this project's AGENTS.override.md is what Codex reads here, instead of \
                 AGENTS.md: no block is written for Codex (EnvCloak never writes into an \
                 override): add the block to it yourself, or remove it and run this again",
            ));
        } else {
            let file = codex_file_in(dir, &fallbacks).unwrap_or_else(|| dir.join("AGENTS.md"));
            let budget = CodexBudget {
                limit,
                before: codex_files_above(dir, &fallbacks),
                shadowed_by: Some(dir.join("AGENTS.override.md")),
            };
            add(file, Some(budget), "Codex");
        }
    }
    ProjectPlan {
        dir: dir.to_path_buf(),
        steps,
        notes,
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
    /// What the plan said beside its steps (a file a host reads instead).
    pub notes: Vec<Note>,
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
    /// Places whose cleanup could not be confirmed: a directory beside a
    /// config that could not be listed (so a leftover there is not known
    /// to be gone), or one EnvCloak made that could not be removed. The run
    /// is not complete while one is there (F123); each is a place to look,
    /// never a file to remove.
    pub cleanup_unconfirmed: Vec<PathBuf>,
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
            && self.cleanup_unconfirmed.is_empty()
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
        limit: limit_for(path),
    }
}

/// How much of the file at `path` the writer reads: Claude Code's
/// `.claude.json`, which holds its state for every project, up to
/// [`crate::writer::MAX_HOST_STATE`]; every other file up to
/// [`crate::writer::MAX_FILE`].
fn limit_for(path: &Path) -> usize {
    if path.file_name() == Some(std::ffi::OsStr::new(".claude.json")) {
        crate::writer::MAX_HOST_STATE
    } else {
        crate::writer::MAX_FILE
    }
}

/// The edit of one step, given the file's contents and EnvCloak's record
/// of it.
fn edit_for(
    kind: &StepKind,
) -> impl FnMut(Option<&[u8]>, Option<&FileRecord>) -> Result<Edited, Refusal> + '_ {
    move |before: Option<&[u8]>, rec: Option<&FileRecord>| match kind {
        StepKind::Block { codex } => match match codex {
            Some(b) => {
                b.shadowed()?;
                blocks::insert_within(before.unwrap_or_default(), b.left())
            }
            None => blocks::insert(before.unwrap_or_default()),
        } {
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
        StepKind::ClaudeMcp { entry } => claude_mcp_edit(before, rec, entry.as_ref()),
        StepKind::Withheld(_) => Ok(None),
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

fn run_step(w: &mut Writer<'_>, step: &Step, t: Target, notes: &mut Vec<Note>) -> StepResult {
    let outcome = match &step.kind {
        StepKind::Withheld(r) => Outcome::Refused(r.clone()),
        kind => {
            let mut edit = edit_for(kind);
            w.change(&t, &mut edit)
        }
    };
    if let StepKind::ClaudeMcp { entry: Some(e) } = &step.kind {
        claude_mcp_notes(w, &step.path, e, &outcome, notes);
    }
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
        cleanup_unconfirmed: Vec::new(),
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
                } | StepKind::ClaudeMcp { .. }
            );
            let t = target(
                &step.path,
                hp.host.id(),
                "global".to_owned(),
                host_owned,
                host_name(hp.host),
            );
            results.push(run_step(w, step, t, &mut notes));
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
                run_step(w, step, t, &mut Vec::new())
            })
            .collect();
        report.project = Some(ProjectReport {
            dir: pp.dir.clone(),
            results,
            notes: pp.notes.clone(),
        });
    }
    w.sweep_all();
    let seen = w.cleanup_inspection();
    report.leftovers = seen.leftovers;
    report.cleanup_unconfirmed.extend(seen.uninspected);
    report.cleanup_unconfirmed.sort();
    report.cleanup_unconfirmed.dedup();
    report
}

/// The user-scope MCP entry named `envcloak` (anyone's) in the
/// `.claude.json` at `path`, read beneath its directory as the writer
/// reads it: `None` when there is none, or the file is not there or
/// cannot be read as JSON.
fn claude_entry(path: &Path) -> Option<Value> {
    let root = open_root(path.parent()?).ok()?;
    let (bytes, _) = read_plain(
        &root,
        Path::new(path.file_name()?),
        crate::writer::MAX_HOST_STATE,
    )
    .ok()?;
    claude::registered(&Zeroizing::new(bytes)).ok().flatten()
}

/// Whether the `.claude.json` at `path` holds a user-scope MCP server
/// named `envcloak` (anyone's), read as the installer reads it.
pub fn claude_json_has_server(path: &Path) -> bool {
    claude_entry(path).is_some()
}

/// Whether EnvCloak's record of a file holds its MCP server entry.
fn mcp_edit(e: &Edit) -> bool {
    matches!(e, Edit::JsonMember { key, .. } if key == claude::SERVER)
}

/// The files EnvCloak's state says hold its MCP server entry for Claude
/// Code (each `.claude.json` it was added to: `CLAUDE_CONFIG_DIR` moves
/// it), by their keys.
pub fn claude_registrations(state: &crate::writer::State) -> Vec<String> {
    state
        .files
        .iter()
        .filter(|(_, r)| r.host == Host::ClaudeCode.id() && r.edits.iter().any(mcp_edit))
        .map(|(k, _)| k.clone())
        .collect()
}

/// The edit of Claude Code's `.claude.json` (Codex review: the server was
/// registered through `claude mcp add-json` and `remove` after the file
/// was inspected, so a replacement in between defeated the ownership and
/// backup checks; it now goes through the writer like every other file,
/// its stamp checked at the rename): EnvCloak's server entry
/// `mcpServers.envcloak` added where the name is free (`entry`), or, with
/// `entry` `None` (the enabled plugin carries the server), EnvCloak's
/// earlier entry taken out. An earlier entry of EnvCloak's that this run
/// does not write goes first, while it still holds what EnvCloak wrote;
/// one the person registered, even with EnvCloak's very settings, is
/// never claimed, and one of another value is a conflict.
fn claude_mcp_edit(
    before: Option<&[u8]>,
    rec: Option<&FileRecord>,
    entry: Option<&Value>,
) -> Result<Edited, Refusal> {
    let json = |e: crate::jsonedit::JsonError| Refusal::new(e.name(), e.message());
    let mut doc = match before {
        Some(b) => Doc::parse(b).map_err(json)?,
        None => Doc::empty(),
    };
    let current = |doc: &Doc| -> Option<Value> {
        doc.get(&[claude::MCP_SERVERS, claude::SERVER])
            .and_then(|n| serde_json::from_str(&doc.text()[n.start..n.end]).ok())
    };
    let mut dropped = Vec::new();
    for e in rec.map(|r| r.edits.as_slice()).unwrap_or_default() {
        let Edit::JsonMember {
            path,
            key,
            value,
            created,
        } = e
        else {
            continue;
        };
        if Some(value) == entry && current(&doc).as_ref() == Some(value) {
            // Still the entry this run writes.
            continue;
        }
        let p: Vec<&str> = path.iter().map(String::as_str).collect();
        doc.remove_member(&p, key, value, *created).map_err(json)?;
        dropped.push(e.clone());
    }
    let mut added = Vec::new();
    if let Some(want) = entry {
        match current(&doc) {
            // EnvCloak's, kept above, or the person's own equal entry,
            // which stays theirs.
            Some(v) if &v == want => {}
            Some(_) => {
                return Err(Refusal::new(
                    "conflict",
                    "an MCP server named `envcloak` is already registered in Claude Code, and \
                     EnvCloak did not register it; remove or rename it first",
                ));
            }
            None => {
                let created = doc
                    .add_member(&[claude::MCP_SERVERS], claude::SERVER, want)
                    .map_err(json)?
                    .unwrap_or(0);
                added.push(Edit::JsonMember {
                    path: vec![claude::MCP_SERVERS.to_owned()],
                    key: claude::SERVER.to_owned(),
                    value: want.clone(),
                    created,
                });
            }
        }
    }
    if added.is_empty() && dropped.is_empty() {
        return Ok(None);
    }
    Ok(Some(Change {
        bytes: doc.text().as_bytes().to_vec(),
        added,
        dropped,
    }))
}

/// The notes a Claude Code MCP step adds once it ran: an equal entry the
/// person registered is theirs (`mcp_server_yours`); a refused one says
/// how the person can register the server themselves (`mcp_by_hand`).
fn claude_mcp_notes(
    w: &Writer<'_>,
    path: &Path,
    entry: &Value,
    outcome: &Outcome,
    notes: &mut Vec<Note>,
) {
    match outcome {
        Outcome::Refused(_) => notes.push(note(
            "mcp_by_hand",
            format!(
                "EnvCloak's MCP server was not added to Claude Code's .claude.json (the reason is \
                 above); once that is resolved, run this again, or register it yourself with \
                 Claude Code closed: claude mcp add-json --scope user {} '{}'",
                claude::SERVER,
                entry.to_string().replace('\'', "'\\''")
            ),
        )),
        Outcome::Unchanged => {
            let ours = w
                .state
                .files
                .get(&crate::writer::key(path))
                .is_some_and(|r| r.edits.iter().any(mcp_edit));
            if !ours && claude_entry(path).as_ref() == Some(entry) {
                notes.push(note(
                    "mcp_server_yours",
                    "an MCP server named `envcloak` with EnvCloak's settings is already \
                     registered in Claude Code, and EnvCloak did not register it: it is left as \
                     yours, and `agents uninstall` leaves it",
                ));
            }
        }
        _ => {}
    }
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
        match e {
            Edit::JsonElement {
                path,
                value,
                created,
            } => {
                let p: Vec<&str> = path.iter().map(String::as_str).collect();
                changed |= doc
                    .remove_from_array(&p, value, *created)
                    .map_err(|e| Refusal::new(e.name(), e.message()))?;
            }
            Edit::JsonMember {
                path,
                key,
                value,
                created,
            } => {
                let p: Vec<&str> = path.iter().map(String::as_str).collect();
                changed |= doc
                    .remove_member(&p, key, value, *created)
                    .map_err(|e| Refusal::new(e.name(), e.message()))?;
            }
            _ => {}
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
pub fn uninstall(opts: &Options, w: &mut Writer<'_>) -> Report {
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
        cleanup_unconfirmed: Vec::new(),
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
            // Every file of the host's EnvCloak changed, `.claude.json`
            // included, wherever `CLAUDE_CONFIG_DIR` points now: the
            // state keys each by the file it is in.
            let mut results = undo_files(w, host.id(), "global", host_name(host));
            results.extend(made_dirs_removed(
                w,
                host.id(),
                "global",
                &mut report.cleanup_unconfirmed,
            ));
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
        let mut results = undo_files(w, "project", &scope, "the agent");
        results.extend(made_dirs_removed(
            w,
            "project",
            &scope,
            &mut report.cleanup_unconfirmed,
        ));
        report.project = Some(ProjectReport {
            dir: dir.clone(),
            results,
            notes: Vec::new(),
        });
    }
    w.sweep_all();
    let seen = w.cleanup_inspection();
    report.leftovers = seen.leftovers;
    report.cleanup_unconfirmed.extend(seen.uninspected);
    report.cleanup_unconfirmed.sort();
    report.cleanup_unconfirmed.dedup();
    report
}

/// The directories EnvCloak made for `host`'s files in `scope`, removed
/// once empty, as report lines; those that could not be removed go to
/// `unconfirmed`.
fn made_dirs_removed(
    w: &mut Writer<'_>,
    host: &str,
    scope: &str,
    unconfirmed: &mut Vec<PathBuf>,
) -> Vec<StepResult> {
    let (removed, left) = crate::writer::remove_made_dirs(w, host, scope);
    unconfirmed.extend(left);
    removed
        .into_iter()
        .map(|path| StepResult {
            what: "remove the directory EnvCloak made, now empty".to_owned(),
            path,
            outcome: Outcome::Removed { backup: None },
        })
        .collect()
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

    /// Backups that hand out ids and keep the results recorded.
    #[derive(Default)]
    struct Kept {
        made: usize,
        results: Vec<(String, Vec<u8>)>,
    }

    impl crate::writer::Backups for Kept {
        fn back_up(&mut self, _: &Path, _: &[u8], _: u32) -> Result<String, Refusal> {
            self.made += 1;
            Ok(format!("B{}", self.made))
        }
        fn record(&mut self, id: &str, after: &[u8]) -> Result<(), Refusal> {
            self.results.push((id.to_owned(), after.to_vec()));
            Ok(())
        }
    }

    /// A `.claude.json` Claude Code wrote 10 minutes ago, with the
    /// person's own server in it.
    fn claude_home() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let home = std::fs::canonicalize(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        let path = home.join(".claude.json");
        std::fs::write(
            &path,
            "{\n  \"numStartups\": 3,\n  \"mcpServers\": {\n    \"other\": {\n      \
             \"command\": \"/usr/bin/true\"\n    }\n  }\n}",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        aged(&path);
        (dir, path)
    }

    fn aged(p: &Path) {
        std::fs::File::options()
            .write(true)
            .open(p)
            .and_then(|f| {
                f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(600))
            })
            .unwrap_or_else(|e| panic!("{e}"));
    }

    /// Another program's save of the file at `path`: new contents put
    /// over its name, as Claude Code saves `.claude.json`.
    fn saved_over(path: &Path, text: &str) {
        let tmp = path.with_extension("other-save");
        std::fs::write(&tmp, text).unwrap_or_else(|e| panic!("{e}"));
        std::fs::rename(&tmp, path).unwrap_or_else(|e| panic!("{e}"));
    }

    const REPLACEMENT: &str = "{\"numStartups\": 4, \"mcpServers\": {\"mine\": {}}}";

    fn mcp_target(path: &Path) -> Target {
        target(
            path,
            "claude-code",
            "global".to_owned(),
            true,
            "Claude Code",
        )
    }

    /// Codex's high finding: the server was registered through `claude mcp
    /// add-json` after `.claude.json` was inspected and backed up, so a
    /// save another program made in between was changed or lost
    /// unchecked. Through the writer, a save between the read and the
    /// rename refuses the change: the other program's file stays as it
    /// saved it, nothing of EnvCloak's is recorded, and the backup's
    /// result is the file as it was read (no change made).
    ///
    /// Mutation checked: the writer's replacement checking a stamp read
    /// again just before the rename instead of the one the file was read
    /// with (`replace_file` given a fresh stamp): the other program's save
    /// is overwritten and this fails.
    #[test]
    fn a_save_over_claude_json_while_the_server_is_added_refuses_it() {
        let (_dir, path) = claude_home();
        let entry = claude::mcp_entry(Path::new("/b/envcloak"));
        let read = std::fs::read(&path).unwrap_or_default();
        let mut state = crate::writer::State::default();
        let mut saved = Saved::default();
        let mut backups = Kept::default();
        let mut w = Writer {
            state: &mut state,
            journal: &mut saved,
            backups: &mut backups,
            now: std::time::SystemTime::now(),
        };
        let kind = StepKind::ClaudeMcp {
            entry: Some(entry.clone()),
        };
        let mut edit = edit_for(&kind);
        let mut raced = |before: Option<&[u8]>, rec: Option<&FileRecord>| {
            let out = edit(before, rec);
            saved_over(&path, REPLACEMENT);
            out
        };
        let o = w.change(&mcp_target(&path), &mut raced);
        assert!(
            matches!(&o, Outcome::Refused(r) if r.name == "changed"),
            "{o:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_default(),
            REPLACEMENT
        );
        assert!(w.state.files.is_empty(), "{:?}", w.state.files);
        assert_eq!(backups.results, vec![("B1".to_owned(), read)]);
    }

    /// The same for the removal (Codex's high finding, `claude mcp
    /// remove`): Claude Code saves over `.claude.json` while uninstall
    /// takes EnvCloak's entry out of it: refused, Claude Code's file as it
    /// saved it, and EnvCloak's record kept, so a later uninstall takes the
    /// entry out.
    ///
    /// Mutation checked: as above (the removal is then made over the
    /// host's save, and this fails).
    #[test]
    fn a_save_over_claude_json_while_the_server_is_taken_out_refuses_it() {
        let (_dir, path) = claude_home();
        let entry = claude::mcp_entry(Path::new("/b/envcloak"));
        let mut state = crate::writer::State::default();
        let mut saved = Saved::default();
        let mut backups = Kept::default();
        let mut w = Writer {
            state: &mut state,
            journal: &mut saved,
            backups: &mut backups,
            now: std::time::SystemTime::now(),
        };
        let kind = StepKind::ClaudeMcp {
            entry: Some(entry.clone()),
        };
        let o = w.change(&mcp_target(&path), &mut edit_for(&kind));
        assert!(matches!(o, Outcome::Changed { .. }), "{o:?}");
        assert_eq!(claude_registrations(w.state).len(), 1);
        // Claude Code wrote its own state since, so the undo goes by
        // structure; it saves again while the undo works.
        let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap_or_default())
            .unwrap_or(Value::Null);
        v["numStartups"] = Value::from(5);
        std::fs::write(&path, v.to_string()).unwrap_or_else(|e| panic!("{e}"));
        aged(&path);
        let mut raced = |cur: &[u8], edits: &[Edit], created: bool| {
            let out = structural(cur, edits, created);
            saved_over(&path, REPLACEMENT);
            out
        };
        let u = w.undo(&mcp_target(&path), &mut raced);
        assert!(
            matches!(&u, Outcome::Refused(r) if r.name == "changed"),
            "{u:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_default(),
            REPLACEMENT
        );
        assert_eq!(claude_registrations(w.state).len(), 1);
    }

    /// EnvCloak's entry is EnvCloak's in its own file only, and only while
    /// it holds what EnvCloak wrote: a reinstall with a new entry replaces
    /// its own; an equal entry the person registered is left theirs;
    /// another value is a conflict; with the plugin carrying the server,
    /// EnvCloak's own entry goes and the person's stays; the person's own
    /// edit of EnvCloak's entry makes it theirs, never removed.
    ///
    /// Mutation checked: `Doc::remove_member` without its value
    /// comparison: the person's edited entry is removed and this fails.
    #[test]
    fn the_server_entry_is_envcloaks_only_while_it_holds_what_envcloak_wrote() {
        let entry = claude::mcp_entry(Path::new("/b/envcloak"));
        let newer = claude::mcp_entry(Path::new("/c/envcloak"));
        let base = b"{\"mcpServers\": {\"other\": {}}}".to_vec();
        let run = |before: &[u8], rec: Option<&FileRecord>, e: Option<&Value>| {
            claude_mcp_edit(Some(before), rec, e)
        };
        let record = |edits: Vec<Edit>| FileRecord {
            host: "claude-code".to_owned(),
            scope: "global".to_owned(),
            host_owned: true,
            created: false,
            pre_sha256: String::new(),
            post_sha256: String::new(),
            stamp: None,
            journal: None,
            edits,
            intent: None,
        };
        let Ok(Some(first)) = run(&base, None, Some(&entry)) else {
            panic!("not added");
        };
        let rec = record(first.added.clone());
        // Installed again with a newer path: EnvCloak's own entry replaced.
        let Ok(Some(second)) = run(&first.bytes, Some(&rec), Some(&newer)) else {
            panic!("not replaced");
        };
        let v: Value = serde_json::from_slice(&second.bytes).unwrap_or(Value::Null);
        assert_eq!(v["mcpServers"]["envcloak"], newer);
        assert_eq!(second.dropped, first.added);
        // The same again: nothing.
        assert!(matches!(
            run(&first.bytes, Some(&rec), Some(&entry)),
            Ok(None)
        ));
        // The person's own equal entry, no record: left theirs.
        assert!(matches!(run(&first.bytes, None, Some(&entry)), Ok(None)));
        // Another value, no record: a conflict.
        assert!(matches!(
            run(&first.bytes, None, Some(&newer)),
            Err(r) if r.name == "conflict"
        ));
        // The plugin carries it: EnvCloak's own goes, the person's stays.
        let Ok(Some(gone)) = run(&first.bytes, Some(&rec), None) else {
            panic!("not taken out");
        };
        let v: Value = serde_json::from_slice(&gone.bytes).unwrap_or(Value::Null);
        assert!(v["mcpServers"].get("envcloak").is_none(), "{v}");
        assert!(v["mcpServers"].get("other").is_some(), "{v}");
        assert!(matches!(run(&first.bytes, None, None), Ok(None)));
        // The person edited EnvCloak's entry: theirs now, never removed.
        let mut theirs: Value = serde_json::from_slice(&first.bytes).unwrap_or(Value::Null);
        theirs["mcpServers"]["envcloak"]["timeout"] = Value::from(1);
        let theirs = theirs.to_string().into_bytes();
        match run(&theirs, Some(&rec), None) {
            Ok(Some(c)) => {
                let v: Value = serde_json::from_slice(&c.bytes).unwrap_or(Value::Null);
                assert_eq!(v["mcpServers"]["envcloak"]["timeout"], 1, "{v}");
                assert_eq!(c.dropped, first.added);
            }
            other => panic!("{other:?}"),
        }
        match structural(&theirs, &first.added, false) {
            Ok(Undo::Nothing) => {}
            other => panic!("{other:?}"),
        }
    }

    /// Lesson L-09 for the Codex block (the class of stale derived state,
    /// found sweeping the project-scope finding): the override that
    /// shadows the file, and the sizes of the files Codex reads first,
    /// are read when the block is written, not only when the plan was
    /// made. An override that appeared since refuses the write
    /// (`override_file`); a file read first whose size cannot be read
    /// takes the whole budget, so the block is refused
    /// (`instruction_budget`) rather than written where it may not be read.
    ///
    /// Mutations checked: `shadowed` not called in `edit_for` (the block is
    /// written beside the new override) and an unreadable size counted as
    /// nothing in `left` (the block is written): each fails this.
    #[test]
    fn the_codex_block_reads_its_shadow_and_budget_when_it_is_written() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let root = std::fs::canonicalize(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        let proj = root.join("p");
        std::fs::create_dir(&proj).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(proj.join("AGENTS.md"), "# P\n").unwrap_or_else(|e| panic!("{e}"));
        let home = root.clone().into_os_string();
        let env = move |k: &str| (k == "HOME").then(|| home.clone());
        let l = Locations::new(&env).unwrap_or_else(|_| panic!("no home"));
        let plan = project_plan(&proj, &[Host::Codex], &l);
        let [step] = plan.steps.as_slice() else {
            panic!("{:?}", plan.steps);
        };
        let target = |p: &Path| target(p, "project", "x".to_owned(), false, "the agent");
        let mut state = crate::writer::State::default();
        let mut saved = Saved::default();
        let mut backups = Kept::default();
        let mut w = Writer {
            state: &mut state,
            journal: &mut saved,
            backups: &mut backups,
            now: std::time::SystemTime::now(),
        };
        // The override appears after the plan.
        std::fs::write(proj.join("AGENTS.override.md"), "# O\n")
            .unwrap_or_else(|e| panic!("{e}"));
        let o = w.change(&target(&step.path), &mut edit_for(&step.kind));
        assert!(
            matches!(&o, Outcome::Refused(r) if r.name == "override_file"),
            "{o:?}"
        );
        assert_eq!(
            std::fs::read_to_string(proj.join("AGENTS.md")).unwrap_or_default(),
            "# P\n"
        );
        // A file Codex reads first that cannot be looked at.
        let locked = root.join("locked");
        std::fs::create_dir(&locked).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(locked.join("AGENTS.md"), "# L\n").unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .unwrap_or_else(|e| panic!("{e}"));
        let kind = StepKind::Block {
            codex: Some(CodexBudget {
                limit: codex::DOC_BUDGET,
                before: vec![locked.join("AGENTS.md")],
                shadowed_by: None,
            }),
        };
        let seen = std::fs::metadata(locked.join("AGENTS.md")).is_ok();
        let o = w.change(&target(&root.join("q.md")), &mut edit_for(&kind));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("{e}"));
        if seen {
            eprintln!("skipped: the directory could still be searched (root)");
            return;
        }
        assert!(
            matches!(&o, Outcome::Refused(r) if r.name == "instruction_budget"),
            "{o:?}"
        );
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
