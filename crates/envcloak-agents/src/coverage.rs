//! Coverage reporting (SPEC §7.1; M2 plan task M2-09, decision D-14): what
//! `envcloak agents status` says each agent host's integration covers.
//!
//! For each host and version, six surfaces ([`Surface`]): prompt-to-model,
//! transcript, file read, shell, MCP and output. Each is in one of four
//! states ([`State`]), always with value-free reason tokens ([`Reason`])
//! where they apply, and with the outcome of its probe ([`Outcome`]),
//! kept apart from the state so that a reason never hides a broken probe:
//! `degraded (fails_open_on_timeout, workspace_untrusted; probe=passed)`,
//! and a failed probe reads `probe=failed` and is listed first
//! ([`Coverage::sorted`]).
//!
//! - `active` only when the surface's probe passed on this machine for
//!   this host binary, version and configuration, and nothing degrades
//!   it. A probe that was not run, was run for another binary, version or
//!   configuration (`changed_since_probe`, lesson L-09), or is not
//!   qualified for this version, never gives `active`.
//! - `degraded` when the hooks a surface rests on need trust, can be
//!   switched off, or fail open: the reasons come from [`degraders`], a
//!   pure function of the configuration files and switches a host reads
//!   ([`ConfigSet`], read from the person's real files, read-only, by
//!   [`ConfigSet::read`]).
//! - `unsupported` where the host offers no contract for the surface: a
//!   blocked prompt the host keeps on disk (`persists_blocked_prompt`,
//!   from the transcript probe, or from the host's own documentation
//!   until a probe ran), a sandboxed shell that cannot reach EnvCloak
//!   (`sandbox_blocks_socket`, K-01), or a host with no prompt-rejection
//!   contract at all ([`static_rows`]: Copilot CLI, OpenCode, Goose).
//! - `unverified` otherwise, with its reason.
//!
//! The probe's results are kept per host binary (its SHA-256), version
//! and configuration digest ([`ConfigSet::digest`]) in a cache
//! ([`Cache`]), and recomputed at display: a result for anything else
//! reads `unverified (changed_since_probe)`.
//!
//! EnvCloak's own MCP server gets a line of its own ([`ServerLine`]): how
//! the host lets an agent call `run_with_secrets` (`listed`, `callable` or
//! `needs_host_approval`), and always `outside_host_sandbox`, the result
//! of a probe whose evidence is whether a sentinel that a command
//! `run_with_secrets` started wrote to a path the host's own sandbox
//! denies appeared (D-03, Codex cycle172): it is a qualification result,
//! not an inference from documentation.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::hook::{Event, Host};
use crate::hosts::{claude, codex};
use crate::locations::Locations;

/// A surface the coverage report states separately (SPEC §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Surface {
    /// What the person types reaching the model (`UserPromptSubmit`).
    PromptToModel,
    /// A blocked prompt kept out of the host's local stores.
    Transcript,
    /// Reading an env file through the host's tools.
    FileRead,
    /// The host's shell tool printing the environment.
    Shell,
    /// The host's MCP tool calls.
    Mcp,
    /// What `envcloak run` prints reaching the host, redacted.
    Output,
}

impl Surface {
    /// Every surface, in the order the report lists them.
    pub const ALL: [Surface; 6] = [
        Surface::PromptToModel,
        Surface::Transcript,
        Surface::FileRead,
        Surface::Shell,
        Surface::Mcp,
        Surface::Output,
    ];

    /// Its name in `--json`.
    pub fn name(self) -> &'static str {
        match self {
            Surface::PromptToModel => "prompt_to_model",
            Surface::Transcript => "transcript",
            Surface::FileRead => "file_read",
            Surface::Shell => "shell",
            Surface::Mcp => "mcp",
            Surface::Output => "output",
        }
    }

    /// How the human report names it.
    pub fn shown(self) -> &'static str {
        match self {
            Surface::PromptToModel => "prompt-to-model",
            Surface::Transcript => "transcript",
            Surface::FileRead => "file read",
            Surface::Shell => "shell",
            Surface::Mcp => "MCP",
            Surface::Output => "output",
        }
    }

    /// The surface named `name` in `--json`.
    pub fn from_name(name: &str) -> Option<Surface> {
        Surface::ALL.into_iter().find(|s| s.name() == name)
    }

    /// Whether the surface rests on the host's hooks (every one but
    /// output, which comes only from `envcloak run`'s redaction).
    pub fn hook_based(self) -> bool {
        self != Surface::Output
    }
}

/// A surface's state (SPEC §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum State {
    Active,
    Degraded,
    Unsupported,
    Unverified,
}

impl State {
    /// Every state.
    pub const ALL: [State; 4] = [
        State::Active,
        State::Degraded,
        State::Unsupported,
        State::Unverified,
    ];

    /// Its token (docs/IPC.md, coverage tokens).
    pub fn name(self) -> &'static str {
        match self {
            State::Active => "active",
            State::Degraded => "degraded",
            State::Unsupported => "unsupported",
            State::Unverified => "unverified",
        }
    }

    /// The state whose token is `token`.
    pub fn from_name(token: &str) -> Option<State> {
        State::ALL.into_iter().find(|s| s.name() == token)
    }
}

/// A reason token (docs/IPC.md, coverage tokens: one registry, no other
/// spelling). None names a value, a path or a file's contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
    /// Codex runs a non-managed hook only once the person trusts it, and
    /// records the trust where EnvCloak cannot read it.
    HooksUntrusted,
    /// Interactive Claude Code holds back every settings-file hook until
    /// the folder's workspace trust is accepted; where it records that is
    /// not documented for the pinned version, so this always applies.
    WorkspaceUntrusted,
    /// A user setting switches the hooks off (Claude Code's
    /// `disableAllHooks`, Codex's `[features] hooks = false`).
    SwitchedOffUser,
    /// A project setting switches them off.
    SwitchedOffProject,
    /// A local setting switches them off (Claude Code's
    /// `.claude/settings.local.json`).
    SwitchedOffLocal,
    /// A managed or system setting switches every hook off.
    SwitchedOffManaged,
    /// A managed setting allows managed hooks only (Claude Code's
    /// `allowManagedHooksOnly`, Codex's `allow_managed_hooks_only`).
    ManagedOnly,
    /// `CLAUDE_CONFIG_DIR` is set: Claude Code reads its settings from the
    /// directory it names, and a session started with another value, or
    /// none, reads other settings.
    ConfigDirMoved,
    /// A hook that times out lets the action through (both tier-1 hosts;
    /// no fail-closed option a probe here showed blocking).
    FailsOpenOnTimeout,
    /// Codex's `AGENTS.override.md` shadows the instruction block.
    OverrideFile,
    /// The host asks before each call of EnvCloak's tool, or refuses it.
    NeedsHostApproval,
    /// Commands `run_with_secrets` starts run outside the host's sandbox,
    /// as the sentinel probe found.
    OutsideHostSandbox,
    /// The host keeps a blocked prompt in its local stores.
    PersistsBlockedPrompt,
    /// The host's sandbox cannot reach EnvCloak's socket with any
    /// documented allowance (K-01).
    SandboxBlocksSocket,
    /// The output probe needs an approval only a terminal subject can give,
    /// and none was there to give it.
    ProbeNeedsTerminal,
    /// EnvCloak's hook for the surface is not in the host's configuration,
    /// or the program it names is gone (a hook whose command is missing
    /// fails open on both hosts).
    HookMissing,
    /// No probe has run on this machine for this host.
    NotProbed,
    /// The host binary, its version or its configuration changed since the
    /// last probe, so its result no longer says anything (L-09).
    ChangedSinceProbe,
}

impl Reason {
    /// Every reason.
    pub const ALL: [Reason; 18] = [
        Reason::HooksUntrusted,
        Reason::WorkspaceUntrusted,
        Reason::SwitchedOffUser,
        Reason::SwitchedOffProject,
        Reason::SwitchedOffLocal,
        Reason::SwitchedOffManaged,
        Reason::ManagedOnly,
        Reason::ConfigDirMoved,
        Reason::FailsOpenOnTimeout,
        Reason::OverrideFile,
        Reason::NeedsHostApproval,
        Reason::OutsideHostSandbox,
        Reason::PersistsBlockedPrompt,
        Reason::SandboxBlocksSocket,
        Reason::ProbeNeedsTerminal,
        Reason::HookMissing,
        Reason::NotProbed,
        Reason::ChangedSinceProbe,
    ];

    /// Its token (docs/IPC.md, coverage tokens).
    pub fn name(self) -> &'static str {
        match self {
            Reason::HooksUntrusted => "hooks_untrusted",
            Reason::WorkspaceUntrusted => "workspace_untrusted",
            Reason::SwitchedOffUser => "switched_off_user",
            Reason::SwitchedOffProject => "switched_off_project",
            Reason::SwitchedOffLocal => "switched_off_local",
            Reason::SwitchedOffManaged => "switched_off_managed",
            Reason::ManagedOnly => "managed_only",
            Reason::ConfigDirMoved => "config_dir_moved",
            Reason::FailsOpenOnTimeout => "fails_open_on_timeout",
            Reason::OverrideFile => "override_file",
            Reason::NeedsHostApproval => "needs_host_approval",
            Reason::OutsideHostSandbox => "outside_host_sandbox",
            Reason::PersistsBlockedPrompt => "persists_blocked_prompt",
            Reason::SandboxBlocksSocket => "sandbox_blocks_socket",
            Reason::ProbeNeedsTerminal => "probe_needs_terminal",
            Reason::HookMissing => "hook_missing",
            Reason::NotProbed => "not_probed",
            Reason::ChangedSinceProbe => "changed_since_probe",
        }
    }

    /// The reason whose token is `token`.
    pub fn from_name(token: &str) -> Option<Reason> {
        Reason::ALL.into_iter().find(|r| r.name() == token)
    }

    /// Whether this degrader applies to `surface`: a switch, a trust gate
    /// or a timeout of the hooks applies to every surface that rests on
    /// them; an override of the instruction block to those its rules are
    /// about (reading env files, printing the environment).
    pub fn degrades(self, surface: Surface) -> bool {
        match self {
            Reason::HooksUntrusted
            | Reason::WorkspaceUntrusted
            | Reason::SwitchedOffUser
            | Reason::SwitchedOffProject
            | Reason::SwitchedOffLocal
            | Reason::SwitchedOffManaged
            | Reason::ManagedOnly
            | Reason::ConfigDirMoved
            | Reason::FailsOpenOnTimeout => surface.hook_based(),
            Reason::OverrideFile => matches!(surface, Surface::FileRead | Surface::Shell),
            _ => false,
        }
    }
}

/// A probe's outcome, kept apart from the state (SPEC §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// The probe and its control passed.
    Passed,
    /// The probe or its control failed: listed first.
    Failed,
    /// The probe did not run.
    Skipped,
    /// The probe is not qualified for this host version, which is not a
    /// failure.
    NotQualified,
}

impl Outcome {
    /// Its token (docs/IPC.md, coverage tokens).
    pub fn name(self) -> &'static str {
        match self {
            Outcome::Passed => "passed",
            Outcome::Failed => "failed",
            Outcome::Skipped => "skipped",
            Outcome::NotQualified => "not_qualified",
        }
    }

    /// The outcome whose token is `token`.
    pub fn from_name(token: &str) -> Option<Outcome> {
        [
            Outcome::Passed,
            Outcome::Failed,
            Outcome::Skipped,
            Outcome::NotQualified,
        ]
        .into_iter()
        .find(|o| o.name() == token)
    }
}

/// How the host lets an agent call EnvCloak's `run_with_secrets` (D-22:
/// the installer pre-approves no EnvCloak tool).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Availability {
    /// The server is registered; how the host approves its tool could not
    /// be read.
    Listed,
    /// The person approved the tool in the host's own settings: the host
    /// calls it without asking.
    Callable,
    /// The host asks before each call, or refuses it (`codex exec` with
    /// approval policy "never").
    NeedsHostApproval,
}

impl Availability {
    /// Its token (docs/IPC.md, coverage tokens).
    pub fn name(self) -> &'static str {
        match self {
            Availability::Listed => "listed",
            Availability::Callable => "callable",
            Availability::NeedsHostApproval => "needs_host_approval",
        }
    }

    /// The availability whose token is `token`.
    pub fn from_name(token: &str) -> Option<Availability> {
        [
            Availability::Listed,
            Availability::Callable,
            Availability::NeedsHostApproval,
        ]
        .into_iter()
        .find(|a| a.name() == token)
    }
}

macro_rules! token_serde {
    ($t:ty, $to:expr, $from:expr) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str($to(*self))
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = String::deserialize(d)?;
                $from(&text).ok_or_else(|| serde::de::Error::custom("an unknown token"))
            }
        }
    };
}

token_serde!(Surface, Surface::name, Surface::from_name);
token_serde!(Reason, Reason::name, Reason::from_name);
token_serde!(Outcome, Outcome::name, Outcome::from_name);
token_serde!(State, State::name, State::from_name);
token_serde!(Availability, Availability::name, Availability::from_name);

/// One surface as reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceState {
    pub surface: Surface,
    pub state: State,
    /// Sorted by token, each once.
    pub reasons: Vec<Reason>,
    pub probe: Outcome,
}

impl SurfaceState {
    /// A surface in `state` for `reasons` (sorted and made unique here).
    pub fn new(surface: Surface, state: State, reasons: &[Reason], probe: Outcome) -> SurfaceState {
        SurfaceState {
            surface,
            state,
            reasons: sorted(reasons),
            probe,
        }
    }
}

/// Reasons sorted by token, each once: the order every report prints them
/// in (SPEC §7.1's example, `fails_open_on_timeout, workspace_untrusted`).
pub fn sorted(reasons: &[Reason]) -> Vec<Reason> {
    let mut out: Vec<Reason> = reasons.to_vec();
    out.sort_by_key(|r| r.name());
    out.dedup();
    out
}

impl fmt::Display for SurfaceState {
    /// `degraded (fails_open_on_timeout, workspace_untrusted; probe=passed)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (", self.state.name())?;
        for (i, r) in self.reasons.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            f.write_str(r.name())?;
        }
        if !self.reasons.is_empty() {
            f.write_str("; ")?;
        }
        write!(f, "probe={})", self.probe.name())
    }
}

/// What the sentinel probe saw of a command `run_with_secrets` started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sentinel {
    /// The sentinel appeared where the host's sandbox denies its own
    /// commands to write: the command ran outside that sandbox.
    Appeared,
    /// It did not appear.
    Absent,
    /// No sentinel probe ran.
    NotRun,
}

impl Sentinel {
    pub fn name(self) -> &'static str {
        match self {
            Sentinel::Appeared => "appeared",
            Sentinel::Absent => "absent",
            Sentinel::NotRun => "not_run",
        }
    }

    pub fn from_name(name: &str) -> Option<Sentinel> {
        [Sentinel::Appeared, Sentinel::Absent, Sentinel::NotRun]
            .into_iter()
            .find(|s| s.name() == name)
    }
}

token_serde!(Sentinel, Sentinel::name, Sentinel::from_name);

/// The line for EnvCloak's own MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerLine {
    pub availability: Availability,
    /// Always `outside_host_sandbox` (D-03).
    pub reasons: Vec<Reason>,
    /// The sentinel probe's outcome: `outside_host_sandbox` is that
    /// qualification's result for this host version and configuration.
    pub probe: Outcome,
    /// The evidence: whether the sentinel appeared.
    pub sentinel: Sentinel,
}

impl fmt::Display for ServerLine {
    /// `needs_host_approval; outside_host_sandbox (probe=passed, sentinel
    /// appeared)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.availability.name())?;
        for r in &self.reasons {
            write!(f, "; {}", r.name())?;
        }
        write!(f, " (probe={}", self.probe.name())?;
        match self.sentinel {
            Sentinel::NotRun => f.write_str(")"),
            s => write!(f, ", sentinel {})", s.name().replace('_', " ")),
        }
    }
}

/// One host's coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    /// The catalog id (`claude-code`, `codex`, `copilot`, ...).
    pub agent: String,
    /// The version the host reported, when it was read.
    pub version: Option<String>,
    pub surfaces: Vec<SurfaceState>,
    /// EnvCloak's own MCP server, when it is registered for the host.
    pub envcloak_server: Option<ServerLine>,
}

impl Coverage {
    /// The surfaces in report order: every failed probe first (SPEC §7.1:
    /// a reason never hides a broken probe), then the rest, each group in
    /// [`Surface::ALL`]'s order.
    #[must_use]
    pub fn sorted(mut self) -> Coverage {
        self.surfaces
            .sort_by_key(|s| (s.probe != Outcome::Failed, s.surface));
        self
    }

    /// The state of `surface`.
    pub fn surface(&self, surface: Surface) -> Option<&SurfaceState> {
        self.surfaces.iter().find(|s| s.surface == surface)
    }
}

// ---------------------------------------------------------------------------
// Configuration: the files and switches a host reads, as facts.

/// What a host's configuration says about one of EnvCloak's hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookState {
    /// EnvCloak's hook is there and the program it runs exists.
    Present,
    /// No EnvCloak hook for it.
    #[default]
    Missing,
    /// EnvCloak's hook is there, but the program it names is gone or not
    /// executable: the host runs it, it fails, and the action goes on.
    CommandMissing,
}

/// EnvCloak's hooks for the events the surfaces rest on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hooks {
    /// `UserPromptSubmit`.
    pub prompt: HookState,
    /// `PreToolUse` for the host's own tools (Claude Code's file and shell
    /// tools; Codex's `Bash`).
    pub tools: HookState,
    /// `PreToolUse` for MCP tools (`mcp__.*`).
    pub mcp: HookState,
}

impl Hooks {
    /// The hook `surface` rests on (none for output).
    pub fn for_surface(&self, surface: Surface) -> Option<HookState> {
        match surface {
            Surface::PromptToModel | Surface::Transcript => Some(self.prompt),
            Surface::FileRead | Surface::Shell => Some(self.tools),
            Surface::Mcp => Some(self.mcp),
            Surface::Output => None,
        }
    }
}

/// EnvCloak's MCP server as the host's configuration has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerFacts {
    /// Registered for the host.
    pub registered: bool,
    /// Whether the person approved `run_with_secrets` in the host's own
    /// settings; `None` when that could not be read.
    pub run_with_secrets_approved: Option<bool>,
}

/// The configuration facts that decide a host's coverage: value-free, so
/// that their digest can key the probe cache and nothing a setting holds
/// is kept. Each `off_*` is true when that level switches every hook off
/// (or holds a file at that level that is not readable, whose switch is
/// then not known: the conservative reading).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSet {
    /// The host's catalog id.
    pub host: String,
    /// Linux, where no pinned host's sandboxed shell reaches the daemon.
    pub linux: bool,
    pub off_user: bool,
    pub off_project: bool,
    pub off_local: bool,
    pub off_managed: bool,
    pub managed_only: bool,
    /// Claude Code: `CLAUDE_CONFIG_DIR` is set.
    pub config_dir_moved: bool,
    /// Codex: `AGENTS.override.md` is there.
    pub override_file: bool,
    /// EnvCloak's hooks are in a managed settings file, which
    /// `allowManagedHooksOnly` and `--safe-mode` keep.
    pub hooks_managed: bool,
    pub hooks: Hooks,
    /// Claude Code: the deny rule `Read(**/.env*)`, which covers `@`
    /// mentions no hook sees.
    pub read_deny: bool,
    /// The host's shell runs in its sandbox by default (Claude Code's
    /// `sandbox.enabled`; Codex unless `sandbox_mode` is
    /// `danger-full-access`).
    pub sandboxed_shell: bool,
    pub server: ServerFacts,
}

impl ConfigSet {
    /// The digest that keys the probe cache: SHA-256 of these facts, as
    /// JSON. Any change in what decides coverage changes it.
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        hex(&Sha256::digest(&bytes))
    }
}

/// Every reason the configuration gives, sorted: the switches the host
/// documents (D-14: Claude Code's user, project, local and managed
/// `disableAllHooks`, managed `allowManagedHooksOnly` and
/// `CLAUDE_CONFIG_DIR`; Codex's hook trust, `[features] hooks = false`,
/// `allow_managed_hooks_only` and `AGENTS.override.md`), the trust gates,
/// and the timeout every hook fails open on. Pure: the same set always
/// gives the same reasons, so M2-28 applies it to the person's files.
pub fn degraders(cs: &ConfigSet) -> Vec<Reason> {
    let mut out = BTreeSet::new();
    let host = Host::from_id(&cs.host);
    for (on, r) in [
        (cs.off_user, Reason::SwitchedOffUser),
        (cs.off_project, Reason::SwitchedOffProject),
        (cs.off_local, Reason::SwitchedOffLocal),
        (cs.off_managed, Reason::SwitchedOffManaged),
        (cs.managed_only && !cs.hooks_managed, Reason::ManagedOnly),
        (cs.config_dir_moved, Reason::ConfigDirMoved),
        (cs.override_file, Reason::OverrideFile),
    ] {
        if on {
            out.insert(r);
        }
    }
    match host {
        // Interactive sessions run no settings-file hook until the
        // folder's trust is accepted, and where Claude Code records that
        // is not documented for the pinned version (D-14).
        Some(Host::ClaudeCode) => {
            out.insert(Reason::WorkspaceUntrusted);
        }
        // Codex records trust against each hook's hash where its docs do
        // not say: the person's hooks read untrusted until it is
        // observable (M2 plan M2-09, risks).
        Some(Host::Codex) => {
            out.insert(Reason::HooksUntrusted);
        }
        None => {}
    }
    if host.is_some() {
        out.insert(Reason::FailsOpenOnTimeout);
    }
    sorted(&out.into_iter().collect::<Vec<_>>())
}

// ---------------------------------------------------------------------------
// Reading the configuration (read-only).

/// The most of one settings file read.
const MAX_SETTINGS: u64 = 4 * 1024 * 1024;
/// The most of Claude Code's `.claude.json` read: it holds the host's
/// state for every project.
const MAX_CLAUDE_JSON: u64 = 64 * 1024 * 1024;

/// One configuration file as read.
#[derive(Debug)]
enum Read {
    Absent,
    /// There, but not a regular file of readable JSON or TOML within the
    /// cap: what it sets is not known.
    Unreadable,
    Json(Value),
    Toml(toml_edit::DocumentMut),
}

fn read_capped(path: &Path, cap: u64) -> Option<Option<Zeroizing<Vec<u8>>>> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(None),
        Err(_) => return None,
    };
    if !meta.is_file() || meta.len() > cap {
        return None;
    }
    let f = std::fs::File::open(path).ok()?;
    let mut bytes = Zeroizing::new(Vec::new());
    f.take(cap + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > cap {
        return None;
    }
    Some(Some(bytes))
}

fn read_json(path: &Path, cap: u64) -> Read {
    match read_capped(path, cap) {
        Some(None) => Read::Absent,
        None => Read::Unreadable,
        Some(Some(b)) => serde_json::from_slice(&b).map_or(Read::Unreadable, Read::Json),
    }
}

fn read_toml(path: &Path) -> Read {
    match read_capped(path, MAX_SETTINGS) {
        Some(None) => Read::Absent,
        None => Read::Unreadable,
        Some(Some(b)) => std::str::from_utf8(&b)
            .ok()
            .and_then(|t| t.parse::<toml_edit::DocumentMut>().ok())
            .map_or(Read::Unreadable, Read::Toml),
    }
}

/// Whether the program a hook command starts (`<path> hook --host ...`,
/// the path quoted for a shell or not) is an executable file.
fn command_present(cmd: &str) -> bool {
    let exe = match cmd.strip_prefix('\'') {
        Some(rest) => {
            // `'...'` with `'\''` for each quote inside.
            let mut out = String::new();
            let mut rest = rest;
            loop {
                let Some(end) = rest.find('\'') else {
                    return false;
                };
                out.push_str(&rest[..end]);
                rest = &rest[end + 1..];
                if let Some(r) = rest.strip_prefix("\\''") {
                    out.push('\'');
                    rest = r;
                } else {
                    break;
                }
            }
            out
        }
        None => match cmd.split_once(' ') {
            Some((exe, _)) => exe.to_owned(),
            None => return false,
        },
    };
    let p = Path::new(&exe);
    p.is_absolute()
        && std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// EnvCloak's hook for `event` among `groups` (a host's list of hook
/// groups for one event), for the tool matcher `matcher` (`None` for an
/// event without one): its state.
fn hook_in(groups: Option<&Value>, host: Host, event: Event, matcher: Option<&str>) -> HookState {
    let tail = format!(" hook --host {} --event {}", host.id(), event.name());
    let mut best = HookState::Missing;
    for group in groups.and_then(Value::as_array).into_iter().flatten() {
        let group_matcher = group.get("matcher").and_then(Value::as_str);
        if matcher.is_some() && group_matcher != matcher {
            continue;
        }
        for h in group
            .get("hooks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(cmd) = h.get("command").and_then(Value::as_str) else {
                continue;
            };
            if !cmd.ends_with(&tail) {
                continue;
            }
            if command_present(cmd) {
                return HookState::Present;
            }
            best = HookState::CommandMissing;
        }
    }
    best
}

/// The better of two readings of one hook: present anywhere wins.
fn either(a: HookState, b: HookState) -> HookState {
    match (a, b) {
        (HookState::Present, _) | (_, HookState::Present) => HookState::Present,
        (HookState::CommandMissing, _) | (_, HookState::CommandMissing) => {
            HookState::CommandMissing
        }
        _ => HookState::Missing,
    }
}

fn hooks_of(settings: &Value, host: Host, tool_matcher: &str, mcp_matcher: &str) -> Hooks {
    let events = settings.get("hooks");
    let at = |e: Event| events.and_then(|h| h.get(e.name()));
    Hooks {
        prompt: hook_in(
            at(Event::UserPromptSubmit),
            host,
            Event::UserPromptSubmit,
            None,
        ),
        tools: hook_in(
            at(Event::PreToolUse),
            host,
            Event::PreToolUse,
            Some(tool_matcher),
        ),
        mcp: hook_in(
            at(Event::PreToolUse),
            host,
            Event::PreToolUse,
            Some(mcp_matcher),
        ),
    }
}

fn merge_hooks(a: Hooks, b: Hooks) -> Hooks {
    Hooks {
        prompt: either(a.prompt, b.prompt),
        tools: either(a.tools, b.tools),
        mcp: either(a.mcp, b.mcp),
    }
}

/// Where Claude Code reads managed settings on this system.
pub fn claude_managed_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/ClaudeCode")
    } else {
        PathBuf::from("/etc/claude-code")
    }
}

/// Whether a settings value's boolean at `key` is true.
fn flag(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool) == Some(true)
}

impl ConfigSet {
    /// Reads `host`'s configuration for a session in `project` (the
    /// directory of the nearest manifest, or the working directory), from
    /// the files `locations` names and the system directories
    /// (`claude_managed` for Claude Code's managed settings), with `env`
    /// for the switches a host reads from its environment. Read-only; no
    /// value of a setting is kept.
    pub fn read(
        host: Host,
        locations: &Locations,
        claude_managed: &Path,
        project: &Path,
        env: &dyn Fn(&str) -> Option<OsString>,
    ) -> ConfigSet {
        let mut cs = ConfigSet {
            host: host.id().to_owned(),
            linux: !cfg!(target_os = "macos"),
            ..ConfigSet::default()
        };
        match host {
            Host::ClaudeCode => read_claude(&mut cs, locations, claude_managed, project, env),
            Host::Codex => read_codex(&mut cs, locations, project),
        }
        cs
    }
}

fn read_claude(
    cs: &mut ConfigSet,
    l: &Locations,
    managed_dir: &Path,
    project: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) {
    cs.config_dir_moved = env("CLAUDE_CONFIG_DIR").is_some_and(|v| !v.is_empty());
    let mut managed = vec![managed_dir.join("managed-settings.json")];
    if let Ok(rd) = std::fs::read_dir(managed_dir.join("managed-settings.d")) {
        let mut more: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        more.sort();
        managed.extend(more);
    }
    let levels: [(&str, Vec<PathBuf>); 4] = [
        ("user", vec![l.claude_settings()]),
        (
            "project",
            vec![project.join(".claude").join("settings.json")],
        ),
        (
            "local",
            vec![project.join(".claude").join("settings.local.json")],
        ),
        ("managed", managed),
    ];
    let mut sandbox: [Option<bool>; 4] = [None; 4];
    let mut plugin = false;
    for (i, (level, files)) in levels.iter().enumerate() {
        for path in files {
            let off = match read_json(path, MAX_SETTINGS) {
                Read::Absent => false,
                // Claude Code does not read a file it cannot parse, so
                // what it would set (EnvCloak's hooks, a switch) is not
                // known: switched off at that level, conservatively.
                Read::Unreadable | Read::Toml(_) => true,
                Read::Json(v) => {
                    let h = hooks_of(
                        &v,
                        Host::ClaudeCode,
                        claude::TOOL_MATCHER,
                        claude::MCP_MATCHER,
                    );
                    if *level == "managed" && h.prompt == HookState::Present {
                        cs.hooks_managed = true;
                    }
                    cs.hooks = merge_hooks(cs.hooks, h);
                    plugin |= claude::plugin_enabled(&v);
                    if v.get("permissions")
                        .and_then(|p| p.get("deny"))
                        .and_then(Value::as_array)
                        .is_some_and(|d| d.iter().any(|r| r.as_str() == Some(claude::READ_DENY)))
                    {
                        cs.read_deny = true;
                    }
                    if *level == "managed" && flag(&v, "allowManagedHooksOnly") {
                        cs.managed_only = true;
                    }
                    if let Some(on) = v
                        .get("sandbox")
                        .and_then(|s| s.get("enabled"))
                        .and_then(Value::as_bool)
                    {
                        sandbox[i] = Some(on);
                    }
                    if let Some(allow) = v
                        .get("permissions")
                        .and_then(|p| p.get("allow"))
                        .and_then(Value::as_array)
                    {
                        if allow.iter().any(|r| {
                            matches!(
                                r.as_str(),
                                Some(
                                    "mcp__envcloak__run_with_secrets"
                                        | "mcp__envcloak__*"
                                        | "mcp__envcloak"
                                )
                            )
                        }) {
                            cs.server.run_with_secrets_approved = Some(true);
                        }
                    }
                    flag(&v, "disableAllHooks")
                }
            };
            if off {
                match *level {
                    "user" => cs.off_user = true,
                    "project" => cs.off_project = true,
                    "local" => cs.off_local = true,
                    _ => cs.off_managed = true,
                }
            }
        }
    }
    // The highest level that says decides (managed, local, project, user).
    cs.sandboxed_shell = sandbox.iter().rev().flatten().next().copied() == Some(true);
    if plugin {
        // The plugin carries EnvCloak's hooks and its MCP server (docs/
        // INSTALLERS.md, "Claude Code plugin").
        cs.hooks = Hooks {
            prompt: HookState::Present,
            tools: HookState::Present,
            mcp: HookState::Present,
        };
        cs.server.registered = true;
    }
    if let Read::Json(v) = read_json(l.claude_json(), MAX_CLAUDE_JSON) {
        if v.get(claude::MCP_SERVERS)
            .and_then(|s| s.get(claude::SERVER))
            .is_some()
        {
            cs.server.registered = true;
        }
    }
    if cs.server.registered && cs.server.run_with_secrets_approved.is_none() {
        cs.server.run_with_secrets_approved = Some(false);
    }
}

fn read_codex(cs: &mut ConfigSet, l: &Locations, project: &Path) {
    cs.override_file = l.codex_instructions_override().exists();
    // `[features] hooks = false`, by layer; `allow_managed_hooks_only` in
    // any layer.
    let off = |r: &Read| match r {
        Read::Absent => false,
        Read::Unreadable | Read::Json(_) => true,
        Read::Toml(d) => {
            d.get("features")
                .and_then(|f| f.get("hooks"))
                .and_then(toml_edit::Item::as_bool)
                == Some(false)
        }
    };
    let managed_only = |r: &Read| match r {
        Read::Toml(d) => {
            d.get("allow_managed_hooks_only")
                .and_then(toml_edit::Item::as_bool)
                == Some(true)
                || d.get("hooks")
                    .and_then(|h| h.get("allow_managed_hooks_only"))
                    .and_then(toml_edit::Item::as_bool)
                    == Some(true)
        }
        _ => false,
    };
    let user = read_toml(&l.codex_config());
    cs.off_user = off(&user);
    cs.managed_only |= managed_only(&user);
    for path in [
        l.codex_system_config(),
        l.codex_managed_config(),
        l.codex_requirements(),
    ] {
        let r = read_toml(&path);
        cs.off_managed |= off(&r);
        cs.managed_only |= managed_only(&r);
    }
    // Each folder from the project up, as Codex reads project layers: a
    // `.codex` that is Codex's own directory is not a project layer.
    let own = std::fs::canonicalize(l.codex_home()).ok();
    let mut dir = Some(project);
    while let Some(d) = dir {
        let dot = d.join(".codex");
        let is_own = own.is_some() && std::fs::canonicalize(&dot).ok() == own;
        if !is_own {
            let r = read_toml(&Locations::codex_project_config(d));
            cs.off_project |= off(&r);
        }
        dir = d.parent();
    }
    if let Read::Toml(d) = &user {
        cs.sandboxed_shell =
            d.get("sandbox_mode").and_then(toml_edit::Item::as_str) != Some("danger-full-access");
        if let Some(server) = d.get("mcp_servers").and_then(|s| s.get(codex::SERVER)) {
            cs.server.registered = true;
            let mode = |item: Option<&toml_edit::Item>| {
                item.and_then(toml_edit::Item::as_str).map(str::to_owned)
            };
            let tool = mode(
                server
                    .get("tools")
                    .and_then(|t| t.get("run_with_secrets"))
                    .and_then(|t| t.get("approval_mode")),
            );
            let default = mode(server.get("default_tools_approval_mode"));
            // A per-tool setting wins over the server's default.
            let effective = tool.or(default);
            cs.server.run_with_secrets_approved = Some(effective.as_deref() == Some("approve"));
        }
    } else {
        cs.sandboxed_shell = true;
    }
    if let Read::Json(v) = read_json(&l.codex_hooks(), MAX_SETTINGS) {
        cs.hooks = hooks_of(&v, Host::Codex, "Bash", "mcp__.*");
    }
}

// ---------------------------------------------------------------------------
// From probe results and configuration to the report.

/// What a probe found for one surface, as the cache keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observed {
    pub surface: Surface,
    pub outcome: Outcome,
    /// The transcript probe found the blocked prompt in the host's stores
    /// (after finding its control there).
    #[serde(default)]
    pub persisted: bool,
    /// Why the probe was skipped, when it was (`probe_needs_terminal`).
    #[serde(default)]
    pub why: Vec<Reason>,
}

/// What the sentinel probe found for EnvCloak's server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerObserved {
    pub outcome: Outcome,
    pub sentinel: Sentinel,
    /// The control: the host's own shell was denied the same kind of
    /// write.
    pub control_denied: bool,
}

/// A probe's results for one host, as the cache keeps them, with what
/// they were for: the host binary's SHA-256, its version and the
/// configuration digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRecord {
    pub host: String,
    pub exe_sha256: String,
    pub version: String,
    pub config_digest: String,
    /// `macos` or `linux`.
    pub os: String,
    pub surfaces: Vec<Observed>,
    pub server: ServerObserved,
    /// The host flags the probe pinned beyond its own, labelled (such as
    /// Codex's trust bypass in a probe home).
    #[serde(default)]
    pub flags: Vec<String>,
}

impl ProbeRecord {
    /// Whether this record is for the host binary, version and
    /// configuration given.
    pub fn is_for(&self, host: &str, exe_sha256: &str, version: &str, digest: &str) -> bool {
        self.host == host
            && self.exe_sha256 == exe_sha256
            && self.version == version
            && self.config_digest == digest
            && self.os == std::env::consts::OS
    }

    fn observed(&self, surface: Surface) -> Option<&Observed> {
        self.surfaces.iter().find(|o| o.surface == surface)
    }
}

/// The probe results the report rests on.
#[derive(Debug, Clone, Copy)]
pub enum Probed<'a> {
    /// A record for this binary, version and configuration.
    Current(&'a ProbeRecord),
    /// Only a record for something else: the host or its configuration
    /// changed since.
    Stale,
    /// None at all.
    None,
}

/// The coverage of tier-1 `host` at `version`, from its configuration and
/// the probe results there are (L-09: recomputed whenever it is shown).
pub fn assemble(host: Host, version: &str, cs: &ConfigSet, probed: Probed<'_>) -> Coverage {
    let degr = degraders(cs);
    let mut surfaces = Vec::new();
    for surface in Surface::ALL {
        surfaces.push(surface_state(host, surface, cs, &degr, probed));
    }
    let envcloak_server = cs.server.registered.then(|| ServerLine {
        availability: match cs.server.run_with_secrets_approved {
            Some(true) => Availability::Callable,
            Some(false) => Availability::NeedsHostApproval,
            None => Availability::Listed,
        },
        reasons: vec![Reason::OutsideHostSandbox],
        probe: match probed {
            Probed::Current(r) => r.server.outcome,
            _ => Outcome::Skipped,
        },
        sentinel: match probed {
            Probed::Current(r) => r.server.sentinel,
            _ => Sentinel::NotRun,
        },
    });
    Coverage {
        agent: host.id().to_owned(),
        version: Some(version.to_owned()),
        surfaces,
        envcloak_server,
    }
    .sorted()
}

fn surface_state(
    host: Host,
    surface: Surface,
    cs: &ConfigSet,
    degr: &[Reason],
    probed: Probed<'_>,
) -> SurfaceState {
    let hook_reasons: Vec<Reason> = degr
        .iter()
        .copied()
        .filter(|r| r.degrades(surface))
        .collect();
    // K-01: on Linux no pinned host's sandboxed shell reaches the daemon.
    let sandbox_blocks = surface == Surface::Shell && cs.linux && cs.sandboxed_shell;
    let hook = cs.hooks.for_surface(surface);
    let missing = matches!(hook, Some(HookState::Missing | HookState::CommandMissing));
    let s = |state, reasons: &[Reason], probe| SurfaceState::new(surface, state, reasons, probe);
    let (outcome, observed) = match probed {
        Probed::Current(r) => match r.observed(surface) {
            Some(o) => (o.outcome, Some(o)),
            None => (Outcome::Skipped, None),
        },
        _ => (Outcome::Skipped, None),
    };
    if sandbox_blocks {
        return s(State::Unsupported, &[Reason::SandboxBlocksSocket], outcome);
    }
    if missing {
        let mut why = vec![Reason::HookMissing];
        why.extend(&hook_reasons);
        return s(State::Unverified, &why, outcome);
    }
    match (probed, observed) {
        (Probed::Current(_), Some(o)) => match o.outcome {
            Outcome::Passed if hook_reasons.is_empty() => s(State::Active, &[], Outcome::Passed),
            Outcome::Passed => s(State::Degraded, &hook_reasons, Outcome::Passed),
            Outcome::Failed if surface == Surface::Transcript && o.persisted => s(
                State::Unsupported,
                &[Reason::PersistsBlockedPrompt],
                Outcome::Failed,
            ),
            Outcome::Failed if hook_reasons.is_empty() => {
                s(State::Unverified, &[], Outcome::Failed)
            }
            Outcome::Failed => s(State::Degraded, &hook_reasons, Outcome::Failed),
            other => {
                let mut why = o.why.clone();
                why.extend(&hook_reasons);
                s(State::Unverified, &why, other)
            }
        },
        _ => {
            // No current result for this surface. What the host documents
            // still holds: Claude Code says a blocked prompt can reach its
            // transcript (SPEC §7.1's table), until a probe here shows
            // otherwise.
            if host == Host::ClaudeCode && surface == Surface::Transcript {
                return s(
                    State::Unsupported,
                    &[Reason::PersistsBlockedPrompt],
                    outcome,
                );
            }
            let mut why = vec![match probed {
                Probed::Stale => Reason::ChangedSinceProbe,
                _ => Reason::NotProbed,
            }];
            why.extend(&hook_reasons);
            s(State::Unverified, &why, outcome)
        }
    }
}

/// The hosts EnvCloak states coverage for without a probe or an
/// installer in this build, by executable name: what their own
/// documentation leaves no contract for (SPEC §7.1's table): no prompt can
/// be rejected (Copilot CLI's command-hook `userPromptSubmitted` output is
/// ignored; OpenCode has no prompt-rejection contract; Goose's
/// `UserPromptSubmit` only observes), so neither the prompt nor its
/// persistence is guarded. Their other surfaces wait for their installers
/// and probes (M2-24): `unverified (not_probed)`.
pub const STATIC_HOSTS: [(&str, &str); 3] = [
    ("copilot", "copilot"),
    ("opencode", "opencode"),
    ("goose", "goose"),
];

/// The static rows of `agent` (a [`STATIC_HOSTS`] id), or `None` for any
/// other.
pub fn static_rows(agent: &str) -> Option<Vec<SurfaceState>> {
    if !STATIC_HOSTS.iter().any(|(id, _)| *id == agent) {
        return None;
    }
    Some(
        Surface::ALL
            .into_iter()
            .map(|surface| match surface {
                Surface::PromptToModel | Surface::Transcript => {
                    SurfaceState::new(surface, State::Unsupported, &[], Outcome::Skipped)
                }
                _ => SurfaceState::new(
                    surface,
                    State::Unverified,
                    &[Reason::NotProbed],
                    Outcome::Skipped,
                ),
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// The cache.

/// The most bytes of the cache read.
const MAX_CACHE: u64 = 1024 * 1024;

/// The probe results kept on this machine: one record per host, the
/// latest. `<data>/agents/coverage.json`, mode 0600.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    pub format: u32,
    pub records: Vec<ProbeRecord>,
}

/// The cache's format.
pub const CACHE_FORMAT: u32 = 1;

impl Cache {
    /// Where the cache is, in EnvCloak's data directory.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("agents").join("coverage.json")
    }

    /// Reads the cache at `path`. A cache that is not there is empty; one
    /// that cannot be read, is too large, is of another format or not of
    /// this shape is empty too, so every surface reads `unverified`: never
    /// a result it does not hold (L-08).
    pub fn load(path: &Path) -> Cache {
        match read_json(path, MAX_CACHE) {
            Read::Json(v) => match serde_json::from_value::<Cache>(v) {
                Ok(c) if c.format == CACHE_FORMAT => c,
                _ => Cache::default(),
            },
            _ => Cache::default(),
        }
    }

    /// The record for `host`, if any.
    pub fn record(&self, host: &str) -> Option<&ProbeRecord> {
        self.records.iter().find(|r| r.host == host)
    }

    /// What the report rests on for `host` with this binary, version and
    /// configuration digest.
    pub fn probed(&self, host: &str, exe_sha256: &str, version: &str, digest: &str) -> Probed<'_> {
        match self.record(host) {
            Some(r) if r.is_for(host, exe_sha256, version, digest) => Probed::Current(r),
            Some(_) => Probed::Stale,
            None => Probed::None,
        }
    }

    /// `record` in place of the host's previous one.
    pub fn put(&mut self, record: ProbeRecord) {
        self.format = CACHE_FORMAT;
        self.records.retain(|r| r.host != record.host);
        self.records.push(record);
        self.records.sort_by(|a, b| a.host.cmp(&b.host));
    }

    /// Writes the cache to `path` (mode 0600, through a temporary file in
    /// the same directory, renamed over it, the directory synced).
    ///
    /// # Errors
    /// When the directory cannot be made or the file written.
    pub fn store(&self, path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let dir = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
        std::fs::create_dir_all(dir)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        let mut rnd = [0u8; 8];
        getrandom::fill(&mut rnd).map_err(std::io::Error::other)?;
        let tmp = dir.join(format!(".coverage.json.{}.tmp", hex(&rnd)));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        let written = f.write_all(&bytes).and_then(|()| f.sync_all());
        drop(f);
        if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, path)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        std::fs::File::open(dir)?.sync_all()
    }
}

/// Lower-case hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        s.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
    }
    s
}

/// The SHA-256 of the file at `path`, read whole (a host binary: the
/// cache's key), or `None` when it cannot be read or is larger than 1
/// GiB.
pub fn file_sha256(path: &Path) -> Option<String> {
    const MAX: u64 = 1024 * 1024 * 1024;
    let f = std::fs::File::open(path).ok()?;
    if f.metadata().ok()?.len() > MAX {
        return None;
    }
    let mut h = Sha256::new();
    let mut r = std::io::BufReader::with_capacity(1 << 20, f.take(MAX + 1));
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        total += n as u64;
        h.update(&buf[..n]);
    }
    (total <= MAX).then(|| hex(&h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cs(host: Host) -> ConfigSet {
        ConfigSet {
            host: host.id().to_owned(),
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

    fn record(host: Host, outcomes: &[(Surface, Outcome, bool)]) -> ProbeRecord {
        ProbeRecord {
            host: host.id().to_owned(),
            exe_sha256: "e".repeat(64),
            version: "1.2.3".to_owned(),
            config_digest: "d".to_owned(),
            os: std::env::consts::OS.to_owned(),
            surfaces: outcomes
                .iter()
                .map(|(s, o, p)| Observed {
                    surface: *s,
                    outcome: *o,
                    persisted: *p,
                    why: Vec::new(),
                })
                .collect(),
            server: ServerObserved {
                outcome: Outcome::Passed,
                sentinel: Sentinel::Appeared,
                control_denied: true,
            },
            flags: Vec::new(),
        }
    }

    fn all(o: Outcome) -> Vec<(Surface, Outcome, bool)> {
        Surface::ALL.iter().map(|s| (*s, o, false)).collect()
    }

    #[test]
    fn tokens_are_one_registry_and_round_trip() {
        let mut seen = BTreeSet::new();
        for t in State::ALL.iter().map(|s| s.name()) {
            assert!(seen.insert(t), "{t}");
        }
        for r in Reason::ALL {
            assert!(
                seen.insert(r.name()) || r == Reason::NeedsHostApproval,
                "{r:?}"
            );
            assert_eq!(Reason::from_name(r.name()), Some(r));
        }
        for o in [
            Outcome::Passed,
            Outcome::Failed,
            Outcome::Skipped,
            Outcome::NotQualified,
        ] {
            assert!(seen.insert(o.name()));
            assert_eq!(Outcome::from_name(o.name()), Some(o));
        }
        for s in Surface::ALL {
            assert_eq!(Surface::from_name(s.name()), Some(s));
        }
        let s = SurfaceState::new(
            Surface::Shell,
            State::Degraded,
            &[Reason::WorkspaceUntrusted, Reason::FailsOpenOnTimeout],
            Outcome::Passed,
        );
        let text = serde_json::to_string(&s).unwrap_or_default();
        assert_eq!(
            text,
            r#"{"surface":"shell","state":"degraded","reasons":["fails_open_on_timeout","workspace_untrusted"],"probe":"passed"}"#
        );
        assert_eq!(serde_json::from_str::<SurfaceState>(&text).ok(), Some(s));
    }

    #[test]
    fn a_state_reads_as_spec_shows_it() {
        let s = SurfaceState::new(
            Surface::PromptToModel,
            State::Degraded,
            &[Reason::WorkspaceUntrusted, Reason::FailsOpenOnTimeout],
            Outcome::Passed,
        );
        assert_eq!(
            s.to_string(),
            "degraded (fails_open_on_timeout, workspace_untrusted; probe=passed)"
        );
        let a = SurfaceState::new(Surface::Output, State::Active, &[], Outcome::Passed);
        assert_eq!(a.to_string(), "active (probe=passed)");
        let line = ServerLine {
            availability: Availability::NeedsHostApproval,
            reasons: vec![Reason::OutsideHostSandbox],
            probe: Outcome::Failed,
            sentinel: Sentinel::Absent,
        };
        assert_eq!(
            line.to_string(),
            "needs_host_approval; outside_host_sandbox (probe=failed, sentinel absent)"
        );
    }

    /// The S4 row, from probe results like the pinned hosts': Claude Code's
    /// hook surfaces degraded by the trust gate and the timeout, its
    /// transcript unsupported, its output active; Codex's degraded by hook
    /// trust and the timeout.
    ///
    /// Mutations checked: `degraders` without the trust gate (`Some(Host::
    /// Codex) => {}`): Codex's surfaces lose `hooks_untrusted` and this
    /// fails; `Outcome::Passed` read as `active` whatever degrades it: the
    /// prompt guard reads `active` and this fails.
    #[test]
    fn passed_probes_under_degraders_read_degraded_and_only_output_is_active() {
        let mut outcomes = all(Outcome::Passed);
        outcomes[1] = (Surface::Transcript, Outcome::Failed, true);
        let c = assemble(
            Host::ClaudeCode,
            "1.2.3",
            &cs(Host::ClaudeCode),
            Probed::Current(&record(Host::ClaudeCode, &outcomes)),
        );
        let shown = |s: Surface| c.surface(s).map(ToString::to_string).unwrap_or_default();
        for s in [
            Surface::PromptToModel,
            Surface::FileRead,
            Surface::Shell,
            Surface::Mcp,
        ] {
            assert_eq!(
                shown(s),
                "degraded (fails_open_on_timeout, workspace_untrusted; probe=passed)",
                "{s:?}"
            );
        }
        assert_eq!(
            shown(Surface::Transcript),
            "unsupported (persists_blocked_prompt; probe=failed)"
        );
        assert_eq!(shown(Surface::Output), "active (probe=passed)");
        // The failed probe is listed first.
        assert_eq!(c.surfaces[0].surface, Surface::Transcript);

        let c = assemble(
            Host::Codex,
            "1.2.3",
            &cs(Host::Codex),
            Probed::Current(&record(Host::Codex, &all(Outcome::Passed))),
        );
        for s in Surface::ALL.into_iter().filter(|s| s.hook_based()) {
            assert_eq!(
                c.surface(s).map(ToString::to_string).unwrap_or_default(),
                "degraded (fails_open_on_timeout, hooks_untrusted; probe=passed)",
                "{s:?}"
            );
        }
        let server = c.envcloak_server.unwrap_or_else(|| panic!("no line"));
        assert_eq!(server.availability, Availability::NeedsHostApproval);
        assert_eq!(server.reasons, [Reason::OutsideHostSandbox]);
    }

    /// A failed probe under a degrader reads `degraded (...;
    /// probe=failed)` and is listed first; without a degrader it is
    /// never `active`.
    ///
    /// Mutation checked: the sort without the failed-first key (by surface
    /// only): the failed MCP probe is listed after the prompt guard and
    /// this fails.
    #[test]
    fn a_failed_probe_shows_and_sorts_first() {
        let mut outcomes = all(Outcome::Passed);
        outcomes[4] = (Surface::Mcp, Outcome::Failed, false);
        outcomes[5] = (Surface::Output, Outcome::Failed, false);
        let c = assemble(
            Host::Codex,
            "1.2.3",
            &cs(Host::Codex),
            Probed::Current(&record(Host::Codex, &outcomes)),
        );
        assert_eq!(c.surfaces[0].surface, Surface::Mcp);
        assert_eq!(c.surfaces[1].surface, Surface::Output);
        assert_eq!(
            c.surfaces[0].to_string(),
            "degraded (fails_open_on_timeout, hooks_untrusted; probe=failed)"
        );
        assert_eq!(c.surfaces[1].to_string(), "unverified (probe=failed)");
        assert!(
            c.surfaces
                .iter()
                .all(|s| s.probe != Outcome::Failed || s.state != State::Active)
        );
    }

    /// No probe, a stale one, a skipped or unqualified one: never
    /// `active`.
    ///
    /// Mutation checked: `Outcome::Skipped` read as passed (`other =>`
    /// arm giving `State::Active`): the skipped output surface reads
    /// `active` and this fails.
    #[test]
    fn only_a_current_passed_probe_is_active() {
        let set = cs(Host::Codex);
        for (probed, why) in [
            (Probed::None, Reason::NotProbed),
            (Probed::Stale, Reason::ChangedSinceProbe),
        ] {
            let c = assemble(Host::Codex, "1.2.3", &set, probed);
            for s in &c.surfaces {
                assert_eq!(s.state, State::Unverified, "{s}");
                assert!(s.reasons.contains(&why), "{s}");
                assert_eq!(s.probe, Outcome::Skipped);
            }
        }
        let rec = record(
            Host::Codex,
            &[
                (Surface::Output, Outcome::Skipped, false),
                (Surface::Shell, Outcome::NotQualified, false),
            ],
        );
        let c = assemble(Host::Codex, "1.2.3", &set, Probed::Current(&rec));
        for s in &c.surfaces {
            assert_ne!(s.state, State::Active, "{s}");
        }
        assert_eq!(
            c.surface(Surface::Shell).map(|s| s.probe),
            Some(Outcome::NotQualified)
        );
        // Claude Code's transcript, unprobed: what its docs say.
        let c = assemble(
            Host::ClaudeCode,
            "1.2.3",
            &cs(Host::ClaudeCode),
            Probed::None,
        );
        assert_eq!(
            c.surface(Surface::Transcript).map(ToString::to_string),
            Some("unsupported (persists_blocked_prompt; probe=skipped)".to_owned())
        );
    }

    /// A transcript probe that passed (the blocked prompt kept out of the
    /// stores, the control found there) is the only way to a transcript
    /// claim; Claude Code's documented gap holds until then.
    #[test]
    fn a_transcript_claim_needs_the_persistence_probe() {
        let rec = record(
            Host::ClaudeCode,
            &[(Surface::Transcript, Outcome::Passed, false)],
        );
        let c = assemble(
            Host::ClaudeCode,
            "1.2.3",
            &cs(Host::ClaudeCode),
            Probed::Current(&rec),
        );
        assert_eq!(
            c.surface(Surface::Transcript).map(|s| s.state),
            Some(State::Degraded)
        );
        let rec = record(
            Host::ClaudeCode,
            &[(Surface::Shell, Outcome::Passed, false)],
        );
        let c = assemble(
            Host::ClaudeCode,
            "1.2.3",
            &cs(Host::ClaudeCode),
            Probed::Current(&rec),
        );
        assert_eq!(
            c.surface(Surface::Transcript).map(|s| s.state),
            Some(State::Unsupported)
        );
    }

    #[test]
    fn every_switch_gives_its_token_and_only_to_hook_surfaces() {
        let base = cs(Host::ClaudeCode);
        for (set, want) in [
            (
                ConfigSet {
                    off_user: true,
                    ..base.clone()
                },
                Reason::SwitchedOffUser,
            ),
            (
                ConfigSet {
                    off_project: true,
                    ..base.clone()
                },
                Reason::SwitchedOffProject,
            ),
            (
                ConfigSet {
                    off_local: true,
                    ..base.clone()
                },
                Reason::SwitchedOffLocal,
            ),
            (
                ConfigSet {
                    off_managed: true,
                    ..base.clone()
                },
                Reason::SwitchedOffManaged,
            ),
            (
                ConfigSet {
                    managed_only: true,
                    ..base.clone()
                },
                Reason::ManagedOnly,
            ),
            (
                ConfigSet {
                    config_dir_moved: true,
                    ..base.clone()
                },
                Reason::ConfigDirMoved,
            ),
            (
                ConfigSet {
                    override_file: true,
                    ..cs(Host::Codex)
                },
                Reason::OverrideFile,
            ),
        ] {
            assert!(degraders(&set).contains(&want), "{want:?}");
            assert!(!degraders(&base).contains(&want) || want == Reason::OverrideFile);
            let host = Host::from_id(&set.host).unwrap_or(Host::Codex);
            let c = assemble(
                host,
                "1.2.3",
                &set,
                Probed::Current(&record(host, &all(Outcome::Passed))),
            );
            assert!(
                c.surface(Surface::Output)
                    .is_some_and(|s| !s.reasons.contains(&want)),
                "{want:?}"
            );
            assert!(
                c.surface(Surface::Shell)
                    .is_some_and(|s| s.reasons.contains(&want)),
                "{want:?}"
            );
        }
        // Hooks kept in a managed file are not stopped by managed-only.
        let kept = ConfigSet {
            managed_only: true,
            hooks_managed: true,
            ..base
        };
        assert!(!degraders(&kept).contains(&Reason::ManagedOnly));
    }

    #[test]
    fn a_missing_hook_and_a_blocked_sandbox_are_said_so() {
        let mut set = cs(Host::ClaudeCode);
        set.hooks.mcp = HookState::CommandMissing;
        set.linux = true;
        set.sandboxed_shell = true;
        let c = assemble(
            Host::ClaudeCode,
            "1.2.3",
            &set,
            Probed::Current(&record(Host::ClaudeCode, &all(Outcome::Passed))),
        );
        let mcp = c.surface(Surface::Mcp).cloned().unwrap_or_else(|| panic!());
        assert_eq!(mcp.state, State::Unverified);
        assert!(mcp.reasons.contains(&Reason::HookMissing));
        assert_eq!(
            c.surface(Surface::Shell).map(ToString::to_string),
            Some("unsupported (sandbox_blocks_socket; probe=passed)".to_owned())
        );
    }

    #[test]
    fn static_hosts_say_unsupported_without_a_probe() {
        let rows = static_rows("copilot").unwrap_or_default();
        assert_eq!(rows.len(), 6);
        assert_eq!(
            rows[0].to_string(),
            "unsupported (probe=skipped)",
            "{:?}",
            rows[0]
        );
        assert_eq!(rows[0].surface, Surface::PromptToModel);
        assert!(rows.iter().all(|r| r.state != State::Active));
        assert!(static_rows("claude-code").is_none());
    }

    /// Mutation checked: `is_for` without the version (`&& self.version
    /// == version` dropped): a record for 1.2.3 is current for 1.2.4 and
    /// this fails.
    #[test]
    fn the_cache_is_keyed_by_binary_version_and_configuration() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = Cache::path(dir.path());
        assert_eq!(Cache::load(&path), Cache::default());
        let mut c = Cache::default();
        let r = record(Host::Codex, &all(Outcome::Passed));
        c.put(r.clone());
        c.store(&path).unwrap_or_else(|e| panic!("{e}"));
        let mode = std::fs::metadata(&path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        assert_eq!(mode, 0o600);
        let back = Cache::load(&path);
        assert_eq!(back, c);
        let e = "e".repeat(64);
        assert!(matches!(
            back.probed("codex", &e, "1.2.3", "d"),
            Probed::Current(_)
        ));
        for (sha, v, d) in [
            ("f".repeat(64), "1.2.3", "d"),
            (e.clone(), "1.2.4", "d"),
            (e.clone(), "1.2.3", "other"),
        ] {
            assert!(
                matches!(back.probed("codex", &sha, v, d), Probed::Stale),
                "{v} {d}"
            );
        }
        assert!(matches!(
            back.probed("claude-code", &e, "1.2.3", "d"),
            Probed::None
        ));
        // A cache of another shape is no cache.
        std::fs::write(&path, b"{\"format\":1,\"records\":[{\"host\":1}]}")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(Cache::load(&path), Cache::default());
        std::fs::write(&path, b"{\"format\":2,\"records\":[]}").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(Cache::load(&path), Cache::default());
    }

    #[test]
    fn the_digest_follows_every_fact() {
        let a = cs(Host::Codex);
        let mut b = a.clone();
        assert_eq!(a.digest(), b.digest());
        b.hooks.prompt = HookState::CommandMissing;
        assert_ne!(a.digest(), b.digest());
        let mut c = a.clone();
        c.server.run_with_secrets_approved = Some(true);
        assert_ne!(a.digest(), c.digest());
    }

    #[test]
    fn hook_commands_are_read_as_a_shell_reads_them() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let exe = dir.path().join("a b").join("envcloak");
        std::fs::create_dir_all(exe.parent().unwrap_or(dir.path()))
            .unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("{e}"));
        let quoted = crate::hosts::shell_quote(&exe.to_string_lossy());
        assert!(command_present(&format!("{quoted} hook --host codex")));
        assert!(!command_present("/nowhere/envcloak hook --host codex"));
        assert!(!command_present("envcloak hook --host codex"));
        assert!(!command_present("'unterminated hook"));
    }
}
