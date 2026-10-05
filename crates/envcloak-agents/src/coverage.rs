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
//! and probe context ([`ConfigSet::fingerprint`]: the facts above, every
//! configuration file the host reads by its SHA-256, the programs
//! EnvCloak's hooks run and the `envcloak` build) in a cache ([`Cache`]),
//! and recomputed at display: a result for anything else, or for a
//! context that cannot be wholly identified, reads `unverified
//! (changed_since_probe)`.
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
    /// The cases of the probe that were not run ([`Case`]), sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<Case>,
}

impl SurfaceState {
    /// A surface in `state` for `reasons` (sorted and made unique here).
    pub fn new(surface: Surface, state: State, reasons: &[Reason], probe: Outcome) -> SurfaceState {
        SurfaceState {
            surface,
            state,
            reasons: sorted(reasons),
            probe,
            skipped: Vec::new(),
        }
    }

    /// The same, with the cases of its probe that were not run.
    #[must_use]
    pub fn with_skipped(mut self, cases: &[Case]) -> SurfaceState {
        let mut c = cases.to_vec();
        c.sort();
        c.dedup();
        self.skipped = c;
        self
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
    /// `degraded (fails_open_on_timeout, workspace_untrusted; probe=passed)`;
    /// a case not run is named after the outcome: `...; probe=passed,
    /// at_mention skipped)`.
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
        write!(f, "probe={}", self.probe.name())?;
        for c in &self.skipped {
            write!(f, ", {} skipped", c.name())?;
        }
        f.write_str(")")
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

/// A case of a surface's probe that was not run, while the rest of the
/// probe was: its outcome is the rest's, and the case is reported apart,
/// never as passed (M2 plan M2-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Case {
    /// Claude Code's file read: the `@README.md` and `@.env` mentions,
    /// where the host does not expand `@` mentions under `-p` (M2-26's
    /// interactive variant covers them).
    AtMention,
    /// The transcript: the prompt history the hosts' interactive sessions
    /// write (`history.jsonl`), which neither `claude -p` nor `codex exec`,
    /// the modes the probe runs in, writes at all (measured on both pinned
    /// hosts, docs/AGENTS.md): the sweep's finding says nothing of it, so
    /// the case is M2-26's interactive variant's (the verifier's round-3
    /// finding: Codex's transcript read passed for its exec stores alone).
    InteractiveHistory,
}

impl Case {
    pub fn name(self) -> &'static str {
        match self {
            Case::AtMention => "at_mention",
            Case::InteractiveHistory => "interactive_history",
        }
    }

    pub fn from_name(name: &str) -> Option<Case> {
        [Case::AtMention, Case::InteractiveHistory]
            .into_iter()
            .find(|c| c.name() == name)
    }
}

token_serde!(Case, Case::name, Case::from_name);

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

/// Which of EnvCloak's hooks are in a managed settings file, which
/// `allowManagedHooksOnly` keeps: each hook apart, since a managed prompt
/// hook keeps no file, shell or MCP hook (Codex review of M2-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedHooks {
    pub prompt: bool,
    pub tools: bool,
    pub mcp: bool,
}

impl ManagedHooks {
    /// Whether the hook `surface` rests on is in a managed file (output
    /// rests on none, so nothing managed-only stops it).
    pub fn for_surface(&self, surface: Surface) -> bool {
        match surface {
            Surface::PromptToModel | Surface::Transcript => self.prompt,
            Surface::FileRead | Surface::Shell => self.tools,
            Surface::Mcp => self.mcp,
            Surface::Output => true,
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

/// How a configuration file was found when it was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileState {
    Absent,
    /// There, but not a regular file within the cap, or not readable.
    Unreadable,
    Read,
}

/// One configuration file the host reads, as the probe context keeps it:
/// what it is to the host, where it is, how it was found, and the SHA-256
/// of its bytes, never a byte of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSeen {
    pub role: String,
    pub path: String,
    pub state: FileState,
    pub sha256: Option<String>,
}

/// A program one of EnvCloak's hooks runs: where it leads, and its
/// SHA-256 (`None` when it is not there: the hook's state says so).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramSeen {
    pub path: String,
    pub sha256: Option<String>,
}

/// The part of a file the host rewrites while it runs that concerns
/// EnvCloak, by the SHA-256 of its canonical JSON: Claude Code's
/// `.claude.json`, where it records its own state on every run (and which
/// it creates in a fresh home; measured on 2.1.280), so the file's bytes
/// say nothing about what a probe ran under, and the registration of
/// EnvCloak's server there says everything (the verifier's round-2
/// finding: a changed command or timeout left the fingerprint as it was).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartSeen {
    pub role: String,
    pub path: String,
    pub sha256: String,
}

/// A store the host keeps what it was sent in, where the transcript probe
/// sweeps for a blocked prompt (D-15): its label, where it is, and, for a
/// folder only some of whose entries are the store (Codex's SQLite files
/// beside its other files), the part of their names it takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSeen {
    pub label: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<String>,
}

/// What a probe's result depends on beyond the facts above (Codex F-132:
/// a hook's timeout, the program it runs, every other setting of the
/// files the host reads): every configuration file the host reads, by its
/// bytes' SHA-256, the parts of the files it rewrites that concern
/// EnvCloak ([`PartSeen`]), every program EnvCloak's hooks run, by its
/// SHA-256, and the host's stores as its settings and environment place
/// them ([`StoreSeen`]: Codex's round-3 review, a store its
/// `CLAUDE_CODE_TMPDIR`, `TMPDIR`, `CODEX_SQLITE_HOME` or a layer's
/// `log_dir` or `sqlite_home` moved left a result current). Nothing a
/// setting holds is kept.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub files: Vec<FileSeen>,
    #[serde(default)]
    pub parts: Vec<PartSeen>,
    pub programs: Vec<ProgramSeen>,
    /// The host's stores, in order, each once.
    #[serde(default)]
    pub stores: Vec<StoreSeen>,
    /// Every store the host may keep a prompt in is in `stores`: false
    /// when a layer of its settings that can move one is there but cannot
    /// be read (a Codex layer EnvCloak cannot read, a file that is not
    /// readable TOML), or a setting that moves one could not be read as a
    /// path. A sweep of `stores` then proves nothing absent.
    #[serde(default)]
    pub stores_known: bool,
    /// Everything a result depends on was identified: false when a
    /// configuration file or a folder of them is there but cannot be read
    /// (what it holds could change unseen), a program a hook runs is there
    /// but cannot be read, or the hooks of EnvCloak's Claude Code plugin
    /// cannot be found. A context not read is not complete either.
    pub complete: bool,
}

impl Context {
    /// Adds a store, once.
    fn store(&mut self, label: &str, path: &Path, names: Option<&str>) {
        let path = path.to_string_lossy().into_owned();
        let names = names.map(str::to_owned);
        if !self
            .stores
            .iter()
            .any(|s| s.path == path && s.names == names)
        {
            self.stores.push(StoreSeen {
                label: label.to_owned(),
                path,
                names,
            });
        }
    }

    /// The stores as a sweep's roots ([`crate::probe::controls::sweep`]).
    pub fn sweep_roots(&self) -> Vec<(PathBuf, Option<String>)> {
        self.stores
            .iter()
            .map(|s| (PathBuf::from(&s.path), s.names.clone()))
            .collect()
    }
}

/// The configuration facts that decide a host's coverage, value-free:
/// their fingerprint ([`ConfigSet::fingerprint`]) keys the probe cache.
/// Each `off_*` is true when that level switches every hook off (or holds
/// a file at that level that is not readable, or a layer EnvCloak cannot
/// read, whose switch is then not known: the conservative reading).
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
    /// Which of EnvCloak's hooks are in a managed settings file, which
    /// `allowManagedHooksOnly` keeps.
    pub managed_hooks: ManagedHooks,
    pub hooks: Hooks,
    /// Claude Code: the deny rule `Read(**/.env*)`, which covers `@`
    /// mentions no hook sees.
    pub read_deny: bool,
    /// Claude Code: a deny rule for its file tools other than EnvCloak's
    /// `Read(**/.env*)`, at any level: a refusal of a `.env` read in the
    /// host's own words may then be that rule's, not EnvCloak's (the
    /// verifier's round-2 finding), so the probe's rule case does not
    /// count it.
    #[serde(default)]
    pub foreign_read_deny: bool,
    /// A `UserPromptSubmit` hook that is not EnvCloak's may run: one is in
    /// a file or layer the host reads hooks from (Codex's hook files and
    /// every config layer's own `[hooks]`; Claude Code's settings), a
    /// plugin other than EnvCloak's is enabled, or a file or layer that
    /// may hold one cannot be read. A blocked prompt the host reports may
    /// then be that hook's, so the prompt probe's witness of the block
    /// does not count where it does not name EnvCloak (Codex's, which
    /// names none).
    #[serde(default)]
    pub foreign_prompt_hook: bool,
    /// The host's shell runs in its sandbox by default (Claude Code's
    /// `sandbox.enabled`; Codex unless its effective `sandbox_mode` is
    /// `danger-full-access`).
    pub sandboxed_shell: bool,
    pub server: ServerFacts,
    pub context: Context,
}

/// The version of what [`ConfigSet::fingerprint`] covers: when it changes,
/// a result kept under the old one is no longer current. 2 since the
/// context holds Claude Code's registration of EnvCloak's server, its
/// `.mcp.json` files and Codex's project hook files, is read for the
/// host's working directory, and is incomplete where a file cannot be
/// read; 3 since it holds the host's stores, wherever its settings and
/// environment place them, the prompt hooks of Codex's TOML layers and
/// plugins, and the switches that take EnvCloak's server or its tool
/// away.
pub const CONTEXT_FORMAT: u32 = 3;

impl ConfigSet {
    /// The probe context's fingerprint, which keys the probe cache (its
    /// configuration digest): the SHA-256 of [`CONTEXT_FORMAT`], these
    /// facts, every configuration file's state and SHA-256 and every
    /// program EnvCloak's hooks run ([`Context`]), and the SHA-256 of
    /// `envcloak`, the build whose hook decisions and `envcloak run`
    /// redaction the surfaces rest on (by where it leads). One routine for
    /// both ends: what a probe's result is kept under (M2-28) and what
    /// `agents status` looks it up by. `None` when the context is not
    /// complete or `envcloak` cannot be read: no result is then current.
    pub fn fingerprint(&self, envcloak: &Path) -> Option<String> {
        if !self.context.complete {
            return None;
        }
        let build = std::fs::canonicalize(envcloak)
            .ok()
            .and_then(|p| file_sha256(&p))?;
        let bytes = serde_json::to_vec(&serde_json::json!({
            "format": CONTEXT_FORMAT,
            "facts": self,
            "envcloak": build,
        }))
        .ok()?;
        Some(hex(&Sha256::digest(&bytes)))
    }
}

/// Every reason the configuration gives, sorted: the switches the host
/// documents (D-14: Claude Code's user, project, local and managed
/// `disableAllHooks`, managed `allowManagedHooksOnly` and
/// `CLAUDE_CONFIG_DIR`; Codex's hook trust, `[features] hooks = false`,
/// `allow_managed_hooks_only` and `AGENTS.override.md`), the trust gates,
/// and the timeout every hook fails open on. Pure: the same set always
/// gives the same reasons, so M2-28 applies it to the person's files.
/// `managed_only` is given when a hook a surface rests on is not in a
/// managed file; [`degraders_for`] gives a surface's own.
pub fn degraders(cs: &ConfigSet) -> Vec<Reason> {
    let mut out = BTreeSet::new();
    let host = Host::from_id(&cs.host);
    let unmanaged = Surface::ALL
        .into_iter()
        .any(|s| s.hook_based() && !cs.managed_hooks.for_surface(s));
    for (on, r) in [
        (cs.off_user, Reason::SwitchedOffUser),
        (cs.off_project, Reason::SwitchedOffProject),
        (cs.off_local, Reason::SwitchedOffLocal),
        (cs.off_managed, Reason::SwitchedOffManaged),
        (cs.managed_only && unmanaged, Reason::ManagedOnly),
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

/// The reasons that degrade `surface`: those of [`degraders`] that apply
/// to it, `managed_only` only when the hook it rests on is not managed.
pub fn degraders_for(cs: &ConfigSet, surface: Surface) -> Vec<Reason> {
    degraders(cs)
        .into_iter()
        .filter(|r| r.degrades(surface))
        .filter(|r| *r != Reason::ManagedOnly || !cs.managed_hooks.for_surface(surface))
        .collect()
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
        Err(e) if not_there(&e) => return Some(None),
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

fn not_there(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

fn parse_json(got: Option<Option<Zeroizing<Vec<u8>>>>) -> Read {
    match got {
        Some(None) => Read::Absent,
        None => Read::Unreadable,
        Some(Some(b)) => serde_json::from_slice(&b).map_or(Read::Unreadable, Read::Json),
    }
}

fn parse_toml(got: Option<Option<Zeroizing<Vec<u8>>>>) -> Read {
    match got {
        Some(None) => Read::Absent,
        None => Read::Unreadable,
        Some(Some(b)) => std::str::from_utf8(&b)
            .ok()
            .and_then(|t| t.parse::<toml_edit::DocumentMut>().ok())
            .map_or(Read::Unreadable, Read::Toml),
    }
}

fn read_json(path: &Path, cap: u64) -> Read {
    parse_json(read_capped(path, cap))
}

impl Context {
    /// Keeps how `path` (a `role` to the host) was found: its state and
    /// its bytes' SHA-256. One that is there but cannot be read leaves the
    /// context incomplete: what it holds could change and nothing here
    /// would (Codex cycle418: unknown content supports no current result).
    fn note(&mut self, role: &str, path: &Path, got: &Option<Option<Zeroizing<Vec<u8>>>>) {
        let (state, sha256) = match got {
            Some(None) => (FileState::Absent, None),
            None => {
                self.complete = false;
                (FileState::Unreadable, None)
            }
            Some(Some(b)) => (FileState::Read, Some(hex(&Sha256::digest(b.as_slice())))),
        };
        self.files.push(FileSeen {
            role: role.to_owned(),
            path: path.to_string_lossy().into_owned(),
            state,
            sha256,
        });
    }

    /// Reads `path` as JSON, keeping it in the context.
    fn json(&mut self, role: &str, path: &Path, cap: u64) -> Read {
        let got = read_capped(path, cap);
        self.note(role, path, &got);
        parse_json(got)
    }

    /// Reads `path` as TOML, keeping it in the context.
    fn toml(&mut self, role: &str, path: &Path) -> Read {
        let got = read_capped(path, MAX_SETTINGS);
        self.note(role, path, &got);
        parse_toml(got)
    }

    /// Keeps a file whose content EnvCloak does not read but whose
    /// presence and bytes decide what the host does (a device profile, an
    /// organization's settings): whether it is there, its SHA-256 when it
    /// can be read. True when it is there, or cannot be looked at.
    fn opaque(&mut self, role: &str, path: &Path) -> bool {
        match std::fs::symlink_metadata(path) {
            Err(e) if not_there(&e) => false,
            Err(_) => {
                self.note(role, path, &None);
                true
            }
            Ok(_) => {
                let got = read_capped(path, MAX_SETTINGS);
                self.note(role, path, &got);
                true
            }
        }
    }

    /// Keeps the programs EnvCloak's hooks run, each by where it leads and
    /// its SHA-256. One that is there but cannot be read leaves the
    /// context incomplete.
    fn programs(&mut self, mut paths: Vec<PathBuf>) {
        paths.sort();
        paths.dedup();
        for p in paths {
            let sha256 = match std::fs::canonicalize(&p) {
                Ok(real) => match file_sha256(&real) {
                    Some(s) => Some(s),
                    None => {
                        self.complete = false;
                        None
                    }
                },
                Err(_) => None,
            };
            self.programs.push(ProgramSeen {
                path: p.to_string_lossy().into_owned(),
                sha256,
            });
        }
    }
}

/// The program a hook command starts (`<path> hook --host ...`, the path
/// quoted for a shell or not), when the command names one by an absolute
/// path.
fn command_program(cmd: &str) -> Option<PathBuf> {
    let exe = match cmd.strip_prefix('\'') {
        Some(rest) => {
            // `'...'` with `'\''` for each quote inside.
            let mut out = String::new();
            let mut rest = rest;
            loop {
                let end = rest.find('\'')?;
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
        None => cmd.split_once(' ')?.0.to_owned(),
    };
    let p = PathBuf::from(exe);
    p.is_absolute().then_some(p)
}

/// Whether the program a hook command starts is an executable file.
fn command_present(cmd: &str) -> bool {
    command_program(cmd).is_some_and(|p| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    })
}

/// EnvCloak's hook for `event` among `groups` (a host's list of hook
/// groups for one event), for the tool matcher `matcher` (`None` for an
/// event without one): its state. The programs its entries name are added
/// to `programs`.
fn hook_in(
    groups: Option<&Value>,
    host: Host,
    event: Event,
    matcher: Option<&str>,
    programs: &mut Vec<PathBuf>,
) -> HookState {
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
            programs.extend(command_program(cmd));
            best = either(
                best,
                if command_present(cmd) {
                    HookState::Present
                } else {
                    HookState::CommandMissing
                },
            );
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

fn hooks_of(
    settings: &Value,
    host: Host,
    tool_matcher: &str,
    mcp_matcher: &str,
    programs: &mut Vec<PathBuf>,
) -> Hooks {
    let events = settings.get("hooks");
    let at = |e: Event| events.and_then(|h| h.get(e.name()));
    Hooks {
        prompt: hook_in(
            at(Event::UserPromptSubmit),
            host,
            Event::UserPromptSubmit,
            None,
            programs,
        ),
        tools: hook_in(
            at(Event::PreToolUse),
            host,
            Event::PreToolUse,
            Some(tool_matcher),
            programs,
        ),
        mcp: hook_in(
            at(Event::PreToolUse),
            host,
            Event::PreToolUse,
            Some(mcp_matcher),
            programs,
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

/// Whether `cmd` is one of EnvCloak's hook commands for `host` and
/// `event`: `<envcloak> hook --host <host> --event <event>`, the program
/// named `envcloak` (by an absolute path, quoted or not, or found on
/// `PATH`, as the plugin's).
fn envcloak_command(cmd: &str, host: Host, event: Event) -> bool {
    let tail = format!(" hook --host {} --event {}", host.id(), event.name());
    cmd.strip_suffix(tail.as_str()).is_some_and(|exe| {
        let exe = exe
            .strip_prefix('\'')
            .and_then(|x| x.strip_suffix('\''))
            .unwrap_or(exe);
        Path::new(exe).file_name() == Some(std::ffi::OsStr::new("envcloak"))
    })
}

/// Whether `settings` (a host's settings or hook file) holds a
/// `UserPromptSubmit` hook that is not EnvCloak's: a command of another
/// program, or a hook of another type (a prompt or an agent hook).
fn foreign_prompt_hook(settings: &Value, host: Host) -> bool {
    settings
        .get("hooks")
        .and_then(|h| h.get(Event::UserPromptSubmit.name()))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|g| {
            g.get("hooks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .any(|h| {
            !h.get("command")
                .and_then(Value::as_str)
                .is_some_and(|c| envcloak_command(c, host, Event::UserPromptSubmit))
        })
}

/// A TOML item as JSON: Codex's hooks written inline in a `config.toml`
/// layer use the schema of its `hooks.json` (pinned 0.159.2; M2-04
/// measured that it runs them), so they are read by the same routine.
fn toml_json(item: &toml_edit::Item) -> Value {
    fn value(v: &toml_edit::Value) -> Value {
        match v {
            toml_edit::Value::String(s) => Value::String(s.value().clone()),
            toml_edit::Value::Integer(i) => Value::from(*i.value()),
            toml_edit::Value::Float(f) => {
                serde_json::Number::from_f64(*f.value()).map_or(Value::Null, Value::Number)
            }
            toml_edit::Value::Boolean(b) => Value::Bool(*b.value()),
            toml_edit::Value::Datetime(d) => Value::String(d.value().to_string()),
            toml_edit::Value::Array(a) => Value::Array(a.iter().map(value).collect()),
            toml_edit::Value::InlineTable(t) => {
                Value::Object(t.iter().map(|(k, v)| (k.to_owned(), value(v))).collect())
            }
        }
    }
    match item {
        toml_edit::Item::None => Value::Null,
        toml_edit::Item::Value(v) => value(v),
        toml_edit::Item::Table(t) => Value::Object(
            t.iter()
                .map(|(k, v)| (k.to_owned(), toml_json(v)))
                .collect(),
        ),
        toml_edit::Item::ArrayOfTables(a) => Value::Array(
            a.iter()
                .map(|t| toml_json(&toml_edit::Item::Table(t.clone())))
                .collect(),
        ),
    }
}

/// Whether a Codex TOML layer holds a `UserPromptSubmit` hook that is not
/// EnvCloak's in its `[hooks]` (the verifier's round-3 finding: these were
/// never read, so a block another program's inline hook gave counted as
/// EnvCloak's), or enables a plugin, whose hooks (`plugin.json`'s
/// `hooks`) EnvCloak does not read: either may give the block Codex
/// reports.
fn codex_layer_prompt_hook(doc: &toml_edit::DocumentMut) -> bool {
    let inline = doc.get("hooks").is_some_and(|h| {
        foreign_prompt_hook(&serde_json::json!({ "hooks": toml_json(h) }), Host::Codex)
    });
    let plugin = doc
        .get("plugins")
        .and_then(toml_edit::Item::as_table_like)
        .is_some_and(|t| {
            t.iter()
                .any(|(_, p)| p.get("enabled").and_then(toml_edit::Item::as_bool) != Some(false))
        });
    inline || plugin
}

/// Whether Claude Code settings enable a plugin other than EnvCloak's,
/// whose hooks EnvCloak does not read.
fn other_plugin_enabled(settings: &Value) -> bool {
    settings
        .get("enabledPlugins")
        .and_then(Value::as_object)
        .is_some_and(|m| {
            m.iter()
                .any(|(k, v)| k.split('@').next() != Some("envcloak") && v.as_bool() != Some(false))
        })
}

/// Whether a Claude Code permission rule names EnvCloak's
/// `run_with_secrets`: the tool itself, or every tool of EnvCloak's server.
fn names_run_with_secrets(rule: &str) -> bool {
    matches!(
        rule,
        "mcp__envcloak__run_with_secrets" | "mcp__envcloak__*" | "mcp__envcloak"
    )
}

/// Whether a Claude Code permission rule is one for its file tools
/// (`Read`, with or without a specifier), which can refuse a `.env` read.
fn file_tool_rule(rule: &str) -> bool {
    rule == "Read" || rule.starts_with("Read(")
}

/// The rules of Claude Code's settings that name `run_with_secrets`.
#[derive(Debug, Clone, Copy, Default)]
struct ToolRules {
    allow: bool,
    ask: bool,
    deny: bool,
}

/// How Claude Code lets an agent call `run_with_secrets`, from the
/// permission mode its settings give (`defaultMode`, the highest level
/// that sets it), whether bypass is switched off
/// (`disableBypassPermissionsMode`), and the rules that name the tool at
/// any level. Measured on the pinned 2.1.280 (`-p`, a tool the rules
/// name): a `deny` or an `ask` rule stops the call in every mode,
/// `bypassPermissions` included; `bypassPermissions` runs it with no rule;
/// `default`, `manual`, `acceptEdits` and `dontAsk` run it only with an
/// `allow` rule. `Some(true)` callable, `Some(false)` asked or refused,
/// `None` not known (`plan`, `auto`, a mode not recognised, or bypass
/// switched off, where what the host does instead was not measured).
fn claude_approval(mode: Option<&str>, bypass_off: bool, rules: ToolRules) -> Option<bool> {
    if rules.deny || rules.ask {
        return Some(false);
    }
    match mode.unwrap_or("default") {
        "bypassPermissions" if !bypass_off => Some(true),
        "default" | "manual" | "acceptEdits" | "dontAsk" => Some(rules.allow),
        _ => None,
    }
}

/// `v` with every object's keys in order, so that the same content always
/// gives the same bytes.
fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonical(&m[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// What Claude Code's `.claude.json` (`v`; `Null` when there is none)
/// says about EnvCloak's server for a session in one of `dirs` (the
/// working directory and every folder above it, the keys Claude Code
/// files a project's local scope under): the user-scope entry, and for
/// each of those folders the local-scope entry and the person's settings
/// about EnvCloak's server there (disabled; a project's servers enabled
/// or disabled). Canonical, with nothing where nothing concerns it, so
/// the host's own bookkeeping in the file, and the file's creation, give
/// the same value. And what the entries say: [`ClaudeRegistration`].
fn claude_registration(v: &Value, dirs: &[PathBuf]) -> (Value, ClaudeRegistration) {
    let server = |x: Option<&Value>| {
        x.and_then(|s| s.get(claude::MCP_SERVERS))
            .and_then(|s| s.get(claude::SERVER))
            .cloned()
    };
    let user = server(Some(v));
    let mut reg = ClaudeRegistration {
        scoped: user.is_some(),
        ..ClaudeRegistration::default()
    };
    let mut projects = serde_json::Map::new();
    let all = v.get("projects").and_then(Value::as_object);
    for d in dirs {
        let key = d.to_string_lossy();
        let Some(e) = all.and_then(|p| p.get(key.as_ref())) else {
            continue;
        };
        let local = server(Some(e));
        reg.scoped |= local.is_some();
        let mut part = serde_json::Map::new();
        if let Some(s) = local {
            part.insert("server".to_owned(), s);
        }
        for (k, name) in [
            ("disabledMcpServers", "disabled"),
            ("enabledMcpjsonServers", "mcpjson_enabled"),
            ("disabledMcpjsonServers", "mcpjson_disabled"),
        ] {
            if names_envcloak(e.get(k)) {
                part.insert(name.to_owned(), Value::Bool(true));
            }
        }
        reg.disabled |= names_envcloak(e.get("disabledMcpServers"));
        reg.mcpjson.read(e);
        if let Some(all) = e.get("enableAllProjectMcpServers").filter(|x| !x.is_null()) {
            part.insert("all_project".to_owned(), all.clone());
        }
        if !part.is_empty() {
            projects.insert(key.into_owned(), Value::Object(part));
        }
    }
    let out = serde_json::json!({
        "user": user.unwrap_or(Value::Null),
        "projects": projects,
    });
    (canonical(&out), reg)
}

/// Whether a list of MCP server names (`disabledMcpServers` and the
/// like) names EnvCloak's server: `envcloak`, or a name that ends in it,
/// as a plugin's server is named (`plugin:envcloak:envcloak`, not measured:
/// read broadly, since a name taken here only takes a callable claim
/// away).
fn names_envcloak(list: Option<&Value>) -> bool {
    list.and_then(Value::as_array).is_some_and(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .any(|n| n == claude::SERVER || n.ends_with(&format!(":{}", claude::SERVER)))
    })
}

/// What Claude Code's `.claude.json` says about EnvCloak's server for the
/// working directory.
#[derive(Debug, Clone, Copy, Default)]
struct ClaudeRegistration {
    /// A user-scope or local-scope entry registers it.
    scoped: bool,
    /// The person switched it off for the directory (`disabledMcpServers`,
    /// which the `/mcp` panel writes per project: Claude Code then does
    /// not connect to it).
    disabled: bool,
    /// The person's approval of a project's `.mcp.json` servers there.
    mcpjson: McpjsonApproval,
}

/// What approves or rejects a server a project's `.mcp.json` registers:
/// Claude Code asks before using one in an interactive session unless
/// `enableAllProjectMcpServers` or `enabledMcpjsonServers` approves it, and
/// `disabledMcpjsonServers` in any settings file rejects it (Claude Code's
/// MCP documentation).
#[derive(Debug, Clone, Copy, Default)]
struct McpjsonApproval {
    approved: bool,
    rejected: bool,
}

impl McpjsonApproval {
    /// Reads the keys from a settings file or a project's entry.
    fn read(&mut self, v: &Value) {
        self.approved |= names_envcloak(v.get("enabledMcpjsonServers"))
            || v.get("enableAllProjectMcpServers").and_then(Value::as_bool) == Some(true);
        self.rejected |= names_envcloak(v.get("disabledMcpjsonServers"));
    }
}

/// Whether an organization's MCP server lists in Claude Code settings
/// (`deniedMcpServers`, `allowedMcpServers`) take EnvCloak's server away:
/// `Some(true)` when a denial names it or an allow list holds names only,
/// none of them its; `None` when an entry matches by command or URL,
/// which this does not resolve; `Some(false)` when neither list is there
/// or names nothing of it.
fn mcp_server_lists(v: &Value) -> Option<bool> {
    let entries = |k: &str| {
        v.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().collect::<Vec<&Value>>())
    };
    fn by_name(e: &Value) -> Option<&str> {
        e.get("serverName").and_then(Value::as_str)
    }
    let mut unknown = false;
    if let Some(denied) = entries("deniedMcpServers") {
        for e in denied {
            match by_name(e) {
                Some(n) if n == claude::SERVER => return Some(true),
                Some(_) => {}
                None => unknown = true,
            }
        }
    }
    if let Some(allowed) = entries("allowedMcpServers") {
        let named = allowed.iter().any(|e| by_name(e) == Some(claude::SERVER));
        let other = allowed.iter().any(|e| by_name(e).is_none());
        match (named, other) {
            (true, _) => {}
            (false, true) => unknown = true,
            (false, false) => return Some(true),
        }
    }
    if unknown { None } else { Some(false) }
}

/// The nearest folder at or above `cwd` holding a `.git` (a folder, or a
/// file as a worktree's): Claude Code reads its local settings there as
/// well as in the working directory (measured on the pinned 2.1.280).
/// `None` when there is none; a `.git` that cannot be looked at leaves
/// the context incomplete, the search stopped there.
fn git_root(cwd: &Path, ctx: &mut Context) -> Option<PathBuf> {
    for d in cwd.ancestors() {
        let dot = d.join(".git");
        match std::fs::symlink_metadata(&dot) {
            Ok(_) => return Some(d.to_path_buf()),
            Err(e) if not_there(&e) => {}
            Err(_) => {
                ctx.note("git_dir", &dot, &None);
                return None;
            }
        }
    }
    None
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
    /// Reads `host`'s configuration for a session whose working directory
    /// is `cwd` (resolved here: Codex review of M2-09, the files of the
    /// directory a host runs in, not of the nearest manifest's), from the
    /// files `locations` names and the system directories
    /// (`claude_managed` for Claude Code's managed settings), with `env`
    /// for the switches a host reads from its environment (and `PATH`,
    /// where the plugin's hooks find `envcloak`). Read-only; no value of a
    /// setting is kept.
    pub fn read(
        host: Host,
        locations: &Locations,
        claude_managed: &Path,
        cwd: &Path,
        env: &dyn Fn(&str) -> Option<OsString>,
    ) -> ConfigSet {
        let mut cs = ConfigSet {
            host: host.id().to_owned(),
            linux: !cfg!(target_os = "macos"),
            context: Context {
                complete: true,
                ..Context::default()
            },
            ..ConfigSet::default()
        };
        let cwd = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
        match host {
            Host::ClaudeCode => read_claude(&mut cs, locations, claude_managed, &cwd, env),
            Host::Codex => read_codex(&mut cs, locations, &cwd),
        }
        cs
    }
}

/// Claude Code's configuration for a session in `cwd`, as the pinned
/// 2.1.280 reads it (measured: docs/INSTALLERS.md, "What `agents status`
/// reads"): the user's settings; the project's settings in the working
/// directory only; the local settings there and at the git root above it;
/// the managed settings and their drop-ins; the user-scope and local-scope
/// registrations of MCP servers in `.claude.json` (the parts that concern
/// EnvCloak's: [`claude_registration`]); every `.mcp.json` from the
/// working directory up; the organization's `managed-mcp.json`; and, with
/// EnvCloak's plugin enabled, its files ([`plugin_context`]).
fn read_claude(
    cs: &mut ConfigSet,
    l: &Locations,
    managed_dir: &Path,
    cwd: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) {
    cs.config_dir_moved = env("CLAUDE_CONFIG_DIR").is_some_and(|v| !v.is_empty());
    let mut managed = vec![managed_dir.join("managed-settings.json")];
    let drop_in = managed_dir.join("managed-settings.d");
    match std::fs::read_dir(&drop_in) {
        Ok(rd) => {
            let mut more = Vec::new();
            for e in rd {
                match e {
                    Ok(e) => more.push(e.path()),
                    // A file there that cannot be listed may switch every
                    // hook off: the conservative reading.
                    Err(_) => {
                        cs.off_managed = true;
                        cs.context.note("claude_managed_dir", &drop_in, &None);
                    }
                }
            }
            more.retain(|p| p.extension().is_some_and(|e| e == "json"));
            more.sort();
            managed.extend(more);
        }
        Err(e) if not_there(&e) => {}
        Err(_) => {
            cs.off_managed = true;
            cs.context.note("claude_managed_dir", &drop_in, &None);
        }
    }
    let mut local = vec![cwd.join(".claude").join("settings.local.json")];
    if let Some(root) = git_root(cwd, &mut cs.context).filter(|r| r != cwd) {
        local.push(root.join(".claude").join("settings.local.json"));
    }
    let levels: [(&str, Vec<PathBuf>); 4] = [
        ("user", vec![l.claude_settings()]),
        ("project", vec![cwd.join(".claude").join("settings.json")]),
        ("local", local),
        ("managed", managed),
    ];
    let mut sandbox: [Option<bool>; 4] = [None; 4];
    let mut mode: [Option<String>; 4] = Default::default();
    let mut rules = ToolRules::default();
    let mut bypass_off = false;
    let mut plugin = false;
    let mut programs = Vec::new();
    let mut mcpjson = McpjsonApproval::default();
    // Whether an organization's server lists take EnvCloak's server away
    // (`Some(true)`), may (`None`), or do not.
    let mut listed_off = Some(false);
    for (i, (level, files)) in levels.iter().enumerate() {
        for path in files {
            let off = match cs
                .context
                .json(&format!("claude_{level}"), path, MAX_SETTINGS)
            {
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
                        &mut programs,
                    );
                    if *level == "managed" {
                        cs.managed_hooks.prompt |= h.prompt == HookState::Present;
                        cs.managed_hooks.tools |= h.tools == HookState::Present;
                        cs.managed_hooks.mcp |= h.mcp == HookState::Present;
                    }
                    cs.hooks = merge_hooks(cs.hooks, h);
                    cs.foreign_prompt_hook |=
                        foreign_prompt_hook(&v, Host::ClaudeCode) || other_plugin_enabled(&v);
                    plugin |= claude::plugin_enabled(&v);
                    mcpjson.read(&v);
                    listed_off = match (listed_off, mcp_server_lists(&v)) {
                        (Some(true), _) | (_, Some(true)) => Some(true),
                        (None, _) | (_, None) => None,
                        _ => Some(false),
                    };
                    let perms = v.get("permissions");
                    let list = |k: &str| {
                        perms
                            .and_then(|p| p.get(k))
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .collect::<Vec<&str>>()
                    };
                    for r in list("deny") {
                        if r == claude::READ_DENY {
                            cs.read_deny = true;
                        } else if file_tool_rule(r) {
                            cs.foreign_read_deny = true;
                        }
                    }
                    rules.deny |= list("deny").into_iter().any(names_run_with_secrets);
                    rules.ask |= list("ask").into_iter().any(names_run_with_secrets);
                    rules.allow |= list("allow").into_iter().any(names_run_with_secrets);
                    if let Some(m) = perms
                        .and_then(|p| p.get("defaultMode"))
                        .and_then(Value::as_str)
                    {
                        mode[i] = Some(m.to_owned());
                    }
                    bypass_off |= perms
                        .and_then(|p| p.get("disableBypassPermissionsMode"))
                        .and_then(Value::as_str)
                        == Some("disable");
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
    let mode = mode.iter().rev().flatten().next().map(String::as_str);
    if plugin {
        // The plugin carries EnvCloak's hooks and its MCP server (docs/
        // INSTALLERS.md, "Claude Code plugin").
        cs.hooks = Hooks {
            prompt: HookState::Present,
            tools: HookState::Present,
            mcp: HookState::Present,
        };
        cs.server.registered = true;
        plugin_context(&mut cs.context, l, env, &mut programs);
    }
    cs.context.programs(programs);
    // The registrations of EnvCloak's server: `.claude.json` by the parts
    // that concern it, every `.mcp.json` from the working directory up
    // (measured: each is read), the organization's `managed-mcp.json`.
    let dirs: Vec<PathBuf> = cwd.ancestors().map(Path::to_path_buf).collect();
    let claude_json = l.claude_json();
    let got = read_capped(claude_json, MAX_CLAUDE_JSON);
    let parsed = match &got {
        Some(None) => Some(Value::Null),
        Some(Some(b)) => serde_json::from_slice::<Value>(b).ok(),
        None => None,
    };
    let mut reg = ClaudeRegistration::default();
    match parsed {
        Some(v) => {
            let (part, found) = claude_registration(&v, &dirs);
            reg = found;
            let bytes = serde_json::to_vec(&part).unwrap_or_default();
            cs.context.parts.push(PartSeen {
                role: "claude_registration".to_owned(),
                path: claude_json.to_string_lossy().into_owned(),
                sha256: hex(&Sha256::digest(&bytes)),
            });
        }
        // There, but not readable JSON within its cap: what it registers
        // is not known, and no result is current.
        None => cs.context.note("claude_registration", claude_json, &None),
    }
    mcpjson.approved |= reg.mcpjson.approved;
    mcpjson.rejected |= reg.mcpjson.rejected;
    let mut project_server = false;
    for d in &dirs {
        if let Read::Json(v) =
            cs.context
                .json("claude_mcp_json", &d.join(".mcp.json"), MAX_SETTINGS)
        {
            project_server |= v
                .get(claude::MCP_SERVERS)
                .and_then(|s| s.get(claude::SERVER))
                .is_some();
        }
    }
    let organization = match cs.context.json(
        "claude_managed_mcp",
        &managed_dir.join("managed-mcp.json"),
        MAX_SETTINGS,
    ) {
        Read::Absent => false,
        Read::Json(v) => {
            cs.server.registered |= v
                .get(claude::MCP_SERVERS)
                .and_then(|s| s.get(claude::SERVER))
                .is_some();
            true
        }
        _ => true,
    };
    cs.server.registered |= reg.scoped || project_server;
    if cs.server.registered {
        cs.server.run_with_secrets_approved = claude_availability(&ClaudeServer {
            organization,
            reg,
            project_server,
            plugin,
            mcpjson,
            listed_off,
            mode,
            bypass_off,
            rules,
        });
    }
    // The stores, where its environment places them (`CLAUDE_CONFIG_DIR`,
    // `CLAUDE_CODE_TMPDIR`): no setting of a file moves one.
    for s in l
        .transcript_sources()
        .into_iter()
        .filter(|s| s.label.starts_with("Claude Code"))
    {
        cs.context.store(&s.label, &s.path, s.names.as_deref());
    }
    cs.context.stores_known = true;
}

/// What decides how Claude Code lets an agent call `run_with_secrets`.
struct ClaudeServer<'a> {
    /// An organization's `managed-mcp.json` is there.
    organization: bool,
    reg: ClaudeRegistration,
    /// A `.mcp.json` from the working directory up registers it.
    project_server: bool,
    /// EnvCloak's plugin, which registers it, is enabled.
    plugin: bool,
    mcpjson: McpjsonApproval,
    listed_off: Option<bool>,
    mode: Option<&'a str>,
    bypass_off: bool,
    rules: ToolRules,
}

/// How Claude Code lets an agent call `run_with_secrets` (Codex's round-3
/// review: a server the person switched off read callable): not known
/// where an organization decides which servers run (not measured), or
/// where its server lists may name it; refused where they do, where the
/// person switched the server off for the directory, or where the only
/// registration is a project's `.mcp.json` that is rejected or not
/// approved (Claude Code asks before using it); else as the permission
/// mode and rules give it ([`claude_approval`]), an `allow` rule counted
/// only for a registration it names (the plugin's server is named apart,
/// so a rule for `mcp__envcloak__` does not allow it).
fn claude_availability(s: &ClaudeServer<'_>) -> Option<bool> {
    if s.organization {
        return None;
    }
    if s.reg.disabled {
        return Some(false);
    }
    match s.listed_off {
        Some(true) => return Some(false),
        None => return None,
        Some(false) => {}
    }
    let named = s.reg.scoped || s.project_server;
    if !s.reg.scoped && !s.plugin && s.project_server && (s.mcpjson.rejected || !s.mcpjson.approved)
    {
        return Some(false);
    }
    let rules = ToolRules {
        allow: s.rules.allow && named,
        ..s.rules
    };
    claude_approval(s.mode, s.bypass_off, rules)
}

/// What EnvCloak's Claude Code plugin adds to the context: Claude Code's
/// record of its installed plugins (`plugins/installed_plugins.json`),
/// the hook file of each install of the `envcloak` plugin it names, the
/// files that register its MCP server there (`.mcp.json`, and the
/// manifest `.claude-plugin/plugin.json`, which can hold servers too: the
/// class of the verifier's round-2 finding, a registration left out), and
/// the `envcloak` those hooks find on `PATH`. Any of them not found leaves
/// the context incomplete: a result kept for a plugin install is current
/// only while all of them are known.
fn plugin_context(
    ctx: &mut Context,
    l: &Locations,
    env: &dyn Fn(&str) -> Option<OsString>,
    programs: &mut Vec<PathBuf>,
) {
    let record = l
        .claude_dir()
        .join("plugins")
        .join("installed_plugins.json");
    let mut found = false;
    if let Read::Json(v) = ctx.json("claude_plugins", &record, MAX_SETTINGS) {
        let installs = v
            .get("plugins")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter(|(k, _)| k.split('@').next() == Some("envcloak"))
            .flat_map(|(_, e)| match e {
                Value::Array(a) => a.clone(),
                other => vec![other.clone()],
            });
        for install in installs {
            let Some(dir) = install.get("installPath").and_then(Value::as_str) else {
                ctx.complete = false;
                continue;
            };
            let hooks = Path::new(dir).join("hooks").join("hooks.json");
            match ctx.json("claude_plugin_hooks", &hooks, MAX_SETTINGS) {
                Read::Json(_) => found = true,
                _ => ctx.complete = false,
            }
            for (role, file) in [
                ("claude_plugin_mcp", Path::new(dir).join(".mcp.json")),
                (
                    "claude_plugin_manifest",
                    Path::new(dir).join(".claude-plugin").join("plugin.json"),
                ),
            ] {
                let got = read_capped(&file, MAX_SETTINGS);
                ctx.note(role, &file, &got);
            }
        }
    }
    match env("PATH").and_then(|p| crate::detect::find_on_path("envcloak", &p)) {
        Some(p) => programs.push(p),
        None => ctx.complete = false,
    }
    if !found {
        ctx.complete = false;
    }
}

/// One of Codex's merged layers, as read.
struct CodexLayer {
    read: Read,
    /// The folder its relative paths are read from: the one that holds it
    /// (Codex's configuration reference: "relative paths resolve from the
    /// config file that declares" them).
    base: PathBuf,
}

/// A store a Codex layer moves (`log_dir`, `sqlite_home`).
enum Moved {
    No,
    To(PathBuf),
    /// Set, but not to a path this reads.
    Unknown,
}

impl CodexLayer {
    fn doc(&self) -> Option<&toml_edit::DocumentMut> {
        match &self.read {
            Read::Toml(d) => Some(d),
            _ => None,
        }
    }

    fn unreadable(&self) -> bool {
        matches!(self.read, Read::Unreadable | Read::Json(_))
    }

    /// Where `key` moves a store to: a path as Codex reads it, `~/` from
    /// the home, a relative one from the layer's folder.
    fn moved(&self, key: &str, home: &Path) -> Moved {
        let Some(item) = self.doc().and_then(|d| d.get(key)) else {
            return Moved::No;
        };
        match item.as_str() {
            Some("") | None => Moved::Unknown,
            Some(v) => Moved::To(match v.strip_prefix('~') {
                Some("") => home.to_path_buf(),
                Some(rest) if rest.starts_with('/') => home.join(rest.trim_start_matches('/')),
                Some(_) => return Moved::Unknown,
                None => self.base.join(v),
            }),
        }
    }

    /// A prompt hook that is not EnvCloak's may be in this layer: one is
    /// in its `[hooks]`, it enables a plugin, or it cannot be read.
    fn prompt_hook(&self) -> bool {
        self.unreadable() || self.doc().is_some_and(codex_layer_prompt_hook)
    }

    /// `[features] hooks = false` (or not readable: not known, so off).
    fn hooks_off(&self) -> bool {
        self.unreadable()
            || self.doc().is_some_and(|d| {
                d.get("features")
                    .and_then(|f| f.get("hooks"))
                    .and_then(toml_edit::Item::as_bool)
                    == Some(false)
            })
    }

    /// `allow_managed_hooks_only = true`, at the top or under `[hooks]`.
    fn managed_only(&self) -> bool {
        self.doc().is_some_and(|d| {
            d.get("allow_managed_hooks_only")
                .and_then(toml_edit::Item::as_bool)
                == Some(true)
                || d.get("hooks")
                    .and_then(|h| h.get("allow_managed_hooks_only"))
                    .and_then(toml_edit::Item::as_bool)
                    == Some(true)
        })
    }

    fn sandbox_mode(&self) -> Option<String> {
        self.doc()?
            .get("sandbox_mode")
            .and_then(toml_edit::Item::as_str)
            .map(str::to_owned)
    }

    /// EnvCloak's server table, when this layer has one.
    fn server(&self) -> Option<&toml_edit::Item> {
        self.doc()?
            .get("mcp_servers")
            .and_then(|s| s.get(codex::SERVER))
    }
}

/// What Codex's merge of `layers` (lowest first; tables merged key by
/// key, any other value replaced by the higher layer's, pinned 0.159.2)
/// gives for what coverage depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CodexMerged {
    unreadable: bool,
    sandbox_mode: Option<String>,
    registered: bool,
    /// The effective approval mode of `run_with_secrets`: its own setting,
    /// else the server's default; [`REFUSED`] where the server is switched
    /// off or the tool is not among those it exposes.
    approval: Option<String>,
}

/// The approval a reading of Codex's merge gives a tool its server does
/// not expose: no approval makes it callable.
const REFUSED: &str = "(refused)";

/// Whether a Codex tool list (`enabled_tools`, `disabled_tools`) names
/// `run_with_secrets`; `None` when it is not a list of names.
fn lists_tool(item: &toml_edit::Item) -> Option<bool> {
    let a = item.as_array()?;
    let mut out = false;
    for v in a {
        out |= v.as_str()? == "run_with_secrets";
    }
    Some(out)
}

/// What Codex's merge of `layers` gives for EnvCloak's server and
/// `run_with_secrets` (Codex's round-3 review: a server switched off, or a
/// tool its lists leave out, read callable): `enabled = false` switches
/// the server off, `enabled_tools` exposes only the tools it names and
/// `disabled_tools` hides those it names (Codex's configuration
/// reference), each the highest layer's that sets it; a list that is not
/// one of names is not known, so it refuses.
fn codex_merge(layers: &[&CodexLayer]) -> CodexMerged {
    let mode =
        |item: Option<&toml_edit::Item>| item.and_then(toml_edit::Item::as_str).map(str::to_owned);
    let mut out = CodexMerged {
        unreadable: false,
        sandbox_mode: None,
        registered: false,
        approval: None,
    };
    let (mut tool, mut default) = (None, None);
    let (mut enabled, mut exposed, mut hidden) = (None, None, None);
    for layer in layers {
        out.unreadable |= layer.unreadable();
        if let Some(m) = layer.sandbox_mode() {
            out.sandbox_mode = Some(m);
        }
        if let Some(server) = layer.server() {
            out.registered = true;
            if let Some(t) = mode(
                server
                    .get("tools")
                    .and_then(|t| t.get("run_with_secrets"))
                    .and_then(|t| t.get("approval_mode")),
            ) {
                tool = Some(t);
            }
            if let Some(d) = mode(server.get("default_tools_approval_mode")) {
                default = Some(d);
            }
            if let Some(e) = server.get("enabled") {
                enabled = Some(e.as_bool());
            }
            if let Some(list) = server.get("enabled_tools") {
                exposed = Some(lists_tool(list));
            }
            if let Some(list) = server.get("disabled_tools") {
                hidden = Some(lists_tool(list));
            }
        }
    }
    let off = enabled.is_some_and(|e| e != Some(true))
        || exposed.is_some_and(|e| e != Some(true))
        || hidden.is_some_and(|h| h != Some(false));
    out.approval = if off {
        Some(REFUSED.to_owned())
    } else {
        tool.or(default)
    };
    out
}

/// Codex's configuration as it merges it (Codex review of M2-09: the
/// sandbox mode and the server's approvals were read from the user's file
/// alone): lowest first, the system file, the user's `config.toml`, a
/// profile file (`--profile`; which one a session names is not in any
/// file, so each, and none, is read), each project's `.codex/config.toml`
/// from the folders above the project down to it (Codex reads them only
/// for a trusted project, which the merge reads both ways), and the
/// legacy managed file on top; `requirements.toml` beside them. A macOS
/// device profile and an organization's settings are layers EnvCloak
/// cannot read (`codex_layers`): with either there, the hooks are taken
/// as switched off by a managed layer, the shell as sandboxed and the
/// server's approval as not known. Each switch is reported at every level
/// that sets it; the sandbox and the approval are what every reading of
/// the merge agrees on, the sandboxed shell when any reading has it, and
/// the approval not known when the readings disagree.
///
/// Hooks: EnvCloak's are read from the user's `hooks.json`, where the
/// installer writes them. Codex also runs the hooks of a trusted
/// project's `.codex/hooks.json`, from the project root down to the
/// working directory (measured on the pinned 0.159.2; an untrusted
/// project's do not run), and a system `hooks.json` sits beside the
/// system layer: each is kept in the context, and a prompt hook there,
/// in any layer's own `[hooks]`, or a plugin a layer enables, is said so
/// ([`ConfigSet::foreign_prompt_hook`]).
///
/// Stores: the catalog's, and every folder a layer's `log_dir` or
/// `sqlite_home` moves one to ([`Context::stores`]).
fn read_codex(cs: &mut ConfigSet, l: &Locations, project: &Path) {
    cs.override_file = l.codex_instructions_override().exists();
    let ctx = &mut cs.context;
    let layer = |ctx: &mut Context, role: &str, path: &Path| CodexLayer {
        read: ctx.toml(role, path),
        base: path.parent().map_or_else(PathBuf::new, Path::to_path_buf),
    };
    let system = layer(ctx, "codex_system", &l.codex_system_config());
    let user = layer(ctx, "codex_user", &l.codex_config());
    let profiles: Vec<CodexLayer> = match l.codex_profile_configs() {
        Ok(mut ps) => {
            ps.sort();
            ps.iter().map(|p| layer(ctx, "codex_profile", p)).collect()
        }
        Err(_) => {
            ctx.note("codex_profiles", l.codex_home(), &None);
            vec![CodexLayer {
                read: Read::Unreadable,
                base: l.codex_home().to_path_buf(),
            }]
        }
    };
    // Each folder from the project up, as Codex reads project layers: a
    // `.codex` that is Codex's own directory is not a project layer.
    let own = std::fs::canonicalize(l.codex_home()).ok();
    let mut projects: Vec<CodexLayer> = Vec::new();
    let mut hook_files = vec![("codex_system_hooks", l.codex_system_hooks())];
    for d in project.ancestors() {
        let dot = d.join(".codex");
        let is_own = own.is_some() && std::fs::canonicalize(&dot).ok() == own;
        if !is_own {
            projects.push(layer(
                ctx,
                "codex_project",
                &Locations::codex_project_config(d),
            ));
            hook_files.push(("codex_project_hooks", dot.join("hooks.json")));
        }
    }
    // Merged from the root down.
    projects.reverse();
    let managed = layer(ctx, "codex_managed", &l.codex_managed_config());
    let requirements = layer(ctx, "codex_requirements", &l.codex_requirements());
    // The layers EnvCloak cannot read.
    let mut unseen = match l.codex_managed_preferences() {
        Ok(ps) => {
            let mut any = false;
            for p in ps {
                any |= ctx.opaque("codex_device_profile", &p);
            }
            any
        }
        Err(_) => {
            ctx.note(
                "codex_device_profiles",
                Path::new("/Library/Managed Preferences"),
                &None,
            );
            true
        }
    };
    unseen |= ctx.opaque("codex_cloud", &l.codex_cloud_config_cache());
    // Codex's rules, which decide what its shell runs before any hook.
    let rules = l.codex_home().join("rules");
    match std::fs::read_dir(&rules) {
        Ok(rd) => {
            let mut files: Vec<PathBuf> = Vec::new();
            for e in rd {
                match e {
                    Ok(e) => files.push(e.path()),
                    Err(_) => ctx.note("codex_rules_dir", &rules, &None),
                }
            }
            files.retain(|p| p.extension().is_some_and(|e| e == "rules"));
            files.sort();
            for f in files {
                let got = read_capped(&f, MAX_SETTINGS);
                ctx.note("codex_rules", &f, &got);
            }
        }
        Err(e) if not_there(&e) => {}
        Err(_) => ctx.note("codex_rules_dir", &rules, &None),
    }
    // The switches, at every level that sets one.
    cs.off_user = user.hooks_off() || profiles.iter().any(CodexLayer::hooks_off);
    cs.off_project = projects.iter().any(CodexLayer::hooks_off);
    cs.off_managed =
        unseen || system.hooks_off() || managed.hooks_off() || requirements.hooks_off();
    cs.managed_only = [&system, &user, &managed, &requirements]
        .into_iter()
        .chain(profiles.iter())
        .chain(projects.iter())
        .any(CodexLayer::managed_only);
    // The merge, each way a session can read it.
    let mut readings = Vec::new();
    let mut choices: Vec<Option<&CodexLayer>> = vec![None];
    choices.extend(profiles.iter().map(Some));
    for profile in &choices {
        for with_projects in [false, true] {
            let mut stack: Vec<&CodexLayer> = vec![&system, &user];
            stack.extend(profile.iter().copied());
            if with_projects {
                stack.extend(projects.iter());
            }
            stack.push(&managed);
            readings.push(codex_merge(&stack));
        }
    }
    let restricted = requirements.doc().is_some_and(|d| {
        d.get("allowed_sandbox_modes")
            .and_then(toml_edit::Item::as_array)
            .is_some_and(|a| !a.iter().any(|v| v.as_str() == Some("danger-full-access")))
    });
    cs.sandboxed_shell = unseen
        || restricted
        || requirements.unreadable()
        || readings
            .iter()
            .any(|r| r.unreadable || r.sandbox_mode.as_deref() != Some("danger-full-access"));
    cs.server.registered = readings.iter().any(|r| r.registered);
    if cs.server.registered {
        let first = readings.first().map(|r| r.approval.clone());
        let agreed = readings
            .iter()
            .all(|r| Some(r.approval.clone()) == first && !r.unreadable);
        cs.server.run_with_secrets_approved = match first {
            Some(a) if agreed && !unseen => Some(a.as_deref() == Some("approve")),
            _ => None,
        };
    }
    let mut programs = Vec::new();
    match cs
        .context
        .json("codex_hooks", &l.codex_hooks(), MAX_SETTINGS)
    {
        Read::Json(v) => {
            cs.hooks = hooks_of(&v, Host::Codex, "Bash", "mcp__.*", &mut programs);
            cs.foreign_prompt_hook |= foreign_prompt_hook(&v, Host::Codex);
        }
        Read::Absent => {}
        // What it holds is not known: a hook of someone else's may be
        // there.
        _ => cs.foreign_prompt_hook = true,
    }
    for (role, file) in hook_files {
        match cs.context.json(role, &file, MAX_SETTINGS) {
            Read::Json(v) => cs.foreign_prompt_hook |= foreign_prompt_hook(&v, Host::Codex),
            Read::Absent => {}
            _ => cs.foreign_prompt_hook = true,
        }
    }
    // Every layer's own `[hooks]` and plugins (the verifier's round-3
    // finding: Codex runs a prompt hook written inline in a `config.toml`,
    // and its block read as EnvCloak's), and the layers EnvCloak cannot
    // read, which may hold either.
    let layers = || {
        [&system, &user, &managed, &requirements]
            .into_iter()
            .chain(profiles.iter())
            .chain(projects.iter())
    };
    cs.foreign_prompt_hook |= unseen || layers().any(CodexLayer::prompt_hook);
    cs.context.programs(programs);
    // The stores (Codex's round-3 review: those a layer other than the
    // user's moved were never swept): the catalog's, where the environment
    // places them (`CODEX_HOME`, `CODEX_SQLITE_HOME`, `TMPDIR`), and every
    // folder a layer's `log_dir` or `sqlite_home` names, whichever reading
    // of the merge a session takes. A layer that cannot be read, or one
    // EnvCloak cannot read, may move one where no sweep looks.
    for s in l
        .transcript_sources()
        .into_iter()
        .filter(|s| s.label.starts_with("Codex"))
    {
        cs.context.store(&s.label, &s.path, s.names.as_deref());
    }
    let mut known = !unseen;
    for layer in layers() {
        known &= !layer.unreadable();
        for (key, label, names) in [
            ("log_dir", "Codex logs, moved by log_dir", None),
            (
                "sqlite_home",
                "Codex SQLite state, moved by sqlite_home",
                Some(".sqlite"),
            ),
        ] {
            match layer.moved(key, l.home()) {
                Moved::No => {}
                Moved::To(dir) => cs.context.store(label, &dir, names),
                Moved::Unknown => known = false,
            }
        }
    }
    cs.context.stores_known = known;
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
    /// The cases of the probe that were not run, while the rest was.
    #[serde(default)]
    pub skipped: Vec<Case>,
}

/// What the sentinel probe found for EnvCloak's server: its outcome and
/// each piece of its evidence, kept so that the outcome shown is the one
/// the evidence supports ([`ServerObserved::supported`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerObserved {
    pub outcome: Outcome,
    pub sentinel: Sentinel,
    /// The host's own shell ran the control: its marker, printed after
    /// its writes, came back in the shell's result.
    pub control_ran: bool,
    /// The same shell made a write where its sandbox lets it (the
    /// writer works).
    pub allowed_write: bool,
    /// And was denied the write beside the sentinel's.
    pub control_denied: bool,
}

impl ServerObserved {
    /// The outcome the evidence supports: `passed` only when the shell
    /// ran, wrote where it may, was denied where the sentinel is written,
    /// and the sentinel appeared; else `failed` (a record that says passed
    /// without its evidence reads failed).
    pub fn supported(&self) -> Outcome {
        let evidence = self.control_ran
            && self.allowed_write
            && self.control_denied
            && self.sentinel == Sentinel::Appeared;
        match self.outcome {
            Outcome::Passed if !evidence => Outcome::Failed,
            o => o,
        }
    }
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
    /// An identity not known (an empty SHA-256, version or digest: a
    /// binary that could not be read, a context not complete) matches no
    /// record, even one that holds the same empty value.
    pub fn is_for(&self, host: &str, exe_sha256: &str, version: &str, digest: &str) -> bool {
        !exe_sha256.is_empty()
            && !version.is_empty()
            && !digest.is_empty()
            && self.host == host
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

impl Probed<'_> {
    /// What it is, as `agents status` says it ([`ProbeStatus`]).
    pub fn status(&self) -> ProbeStatus {
        match self {
            Probed::Current(_) => ProbeStatus::Current,
            Probed::Stale => ProbeStatus::ChangedSinceProbe,
            Probed::None => ProbeStatus::NotProbed,
        }
    }
}

/// Whether a host's states rest on a current probe, as `agents status
/// --json` names it (`probed`; docs/IPC.md, coverage tokens: the last two
/// are the reasons of the same name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeStatus {
    /// A record for this binary, version and configuration.
    Current,
    /// Only one for something else.
    ChangedSinceProbe,
    /// None at all.
    NotProbed,
}

impl ProbeStatus {
    pub fn name(self) -> &'static str {
        match self {
            ProbeStatus::Current => "current",
            ProbeStatus::ChangedSinceProbe => "changed_since_probe",
            ProbeStatus::NotProbed => "not_probed",
        }
    }
}

/// How `agents status` identified a host it reports (`identified_by`;
/// docs/IPC.md, coverage tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Identity {
    /// The version the catalog reads the host's binary for.
    Version,
    /// An executable of the host's name on `PATH`, its version not read.
    ExecutableName,
}

impl Identity {
    pub fn name(self) -> &'static str {
        match self {
            Identity::Version => "version",
            Identity::ExecutableName => "executable_name",
        }
    }
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
            Probed::Current(r) => r.server.supported(),
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
        .filter(|r| *r != Reason::ManagedOnly || !cs.managed_hooks.for_surface(surface))
        .collect();
    // K-01: on Linux no pinned host's sandboxed shell reaches the daemon.
    let sandbox_blocks = surface == Surface::Shell && cs.linux && cs.sandboxed_shell;
    let hook = cs.hooks.for_surface(surface);
    let missing = matches!(hook, Some(HookState::Missing | HookState::CommandMissing));
    let (outcome, observed) = match probed {
        Probed::Current(r) => match r.observed(surface) {
            Some(o) => (o.outcome, Some(o)),
            None => (Outcome::Skipped, None),
        },
        _ => (Outcome::Skipped, None),
    };
    // The cases its probe did not run go with whatever it reads.
    let skipped = observed.map_or(&[][..], |o| o.skipped.as_slice());
    let s = |state, reasons: &[Reason], probe| {
        SurfaceState::new(surface, state, reasons, probe).with_skipped(skipped)
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

/// The cache's format: 2 since a record keys the probe context's
/// fingerprint and keeps the sentinel's evidence and the cases not run, so
/// a record of format 1 is no record.
pub const CACHE_FORMAT: u32 = 2;

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
                    skipped: Vec::new(),
                })
                .collect(),
            server: ServerObserved {
                outcome: Outcome::Passed,
                sentinel: Sentinel::Appeared,
                control_ran: true,
                allowed_write: true,
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
            managed_hooks: ManagedHooks {
                prompt: true,
                tools: true,
                mcp: true,
            },
            ..base.clone()
        };
        assert!(!degraders(&kept).contains(&Reason::ManagedOnly));
        // Each hook apart: a managed prompt hook keeps the prompt guard
        // and the transcript, never the file, shell or MCP hooks.
        let prompt_only = ConfigSet {
            managed_only: true,
            managed_hooks: ManagedHooks {
                prompt: true,
                tools: false,
                mcp: false,
            },
            ..base
        };
        let c = assemble(
            Host::ClaudeCode,
            "1.2.3",
            &prompt_only,
            Probed::Current(&record(Host::ClaudeCode, &all(Outcome::Passed))),
        );
        for surface in Surface::ALL {
            let on = c
                .surface(surface)
                .is_some_and(|s| s.reasons.contains(&Reason::ManagedOnly));
            let want = matches!(surface, Surface::FileRead | Surface::Shell | Surface::Mcp);
            assert_eq!(on, want, "{surface:?}");
            assert_eq!(
                degraders_for(&prompt_only, surface).contains(&Reason::ManagedOnly),
                want,
                "{surface:?}"
            );
        }
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
        std::fs::write(&path, b"{\"format\":3,\"records\":[]}").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(Cache::load(&path), Cache::default());
        // A record of format 1 (before the fingerprint and the sentinel's
        // evidence) is no record.
        let mut v = serde_json::to_value(&c).unwrap_or_default();
        v["format"] = serde_json::json!(1);
        std::fs::write(&path, v.to_string()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(Cache::load(&path), Cache::default());
    }

    /// The fingerprint follows every fact, the context and the build, and
    /// there is none for a context not wholly identified.
    ///
    /// Mutation checked: `fingerprint` without the `envcloak` build (its
    /// `"envcloak"` member dropped): another build gives the same
    /// fingerprint and this fails.
    #[test]
    fn the_fingerprint_follows_every_fact_the_context_and_the_build() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let build = dir.path().join("envcloak");
        std::fs::write(&build, b"build one").unwrap_or_else(|e| panic!("{e}"));
        let mut a = cs(Host::Codex);
        a.context.complete = true;
        let fp = |c: &ConfigSet| c.fingerprint(&build);
        assert!(fp(&a).is_some());
        assert_eq!(fp(&a), fp(&a.clone()));
        let mut b = a.clone();
        b.hooks.prompt = HookState::CommandMissing;
        assert_ne!(fp(&a), fp(&b));
        let mut c = a.clone();
        c.server.run_with_secrets_approved = Some(true);
        assert_ne!(fp(&a), fp(&c));
        let mut d = a.clone();
        d.context.files.push(FileSeen {
            role: "codex_user".to_owned(),
            path: "/h/.codex/config.toml".to_owned(),
            state: FileState::Read,
            sha256: Some("0".repeat(64)),
        });
        let mut e = d.clone();
        e.context.files[0].sha256 = Some("1".repeat(64));
        assert_ne!(fp(&d), fp(&e));
        let before = fp(&a);
        std::fs::write(&build, b"build two").unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(before, fp(&a), "another build, the same fingerprint");
        // Not complete, or no build to read: no fingerprint at all.
        let mut f = a.clone();
        f.context.complete = false;
        assert_eq!(fp(&f), None);
        assert_eq!(a.fingerprint(&dir.path().join("absent")), None);
        assert_eq!(ConfigSet::default().fingerprint(&build), None);
    }

    /// An identity not known matches no record, even one holding the same
    /// empty value (the verifier's finding: an unreadable host binary got
    /// an empty SHA-256, which a record could share).
    ///
    /// Mutation checked: `is_for` without its empty-value refusal: a
    /// record with an empty SHA-256 is current for an unreadable binary and
    /// this fails.
    #[test]
    fn an_unknown_identity_matches_no_record() {
        let mut r = record(Host::Codex, &all(Outcome::Passed));
        r.exe_sha256 = String::new();
        assert!(!r.is_for("codex", "", "1.2.3", "d"));
        let mut c = Cache::default();
        c.put(r);
        assert!(matches!(c.probed("codex", "", "1.2.3", "d"), Probed::Stale));
        let mut r = record(Host::Codex, &all(Outcome::Passed));
        r.config_digest = String::new();
        assert!(!r.is_for("codex", &"e".repeat(64), "1.2.3", ""));
        let mut r = record(Host::Codex, &all(Outcome::Passed));
        r.version = String::new();
        assert!(!r.is_for("codex", &"e".repeat(64), "", "d"));
        // The control: the same record with its identity is current.
        let r = record(Host::Codex, &all(Outcome::Passed));
        assert!(r.is_for("codex", &"e".repeat(64), "1.2.3", "d"));
    }

    /// The server line's outcome is what its evidence supports: a record
    /// that says passed without the shell's run, its allowed write, its
    /// denied write or the sentinel reads failed.
    #[test]
    fn a_server_pass_needs_all_its_evidence() {
        let full = record(Host::Codex, &all(Outcome::Passed));
        assert_eq!(full.server.supported(), Outcome::Passed);
        for strip in 0..4 {
            let mut r = full.clone();
            match strip {
                0 => r.server.control_ran = false,
                1 => r.server.allowed_write = false,
                2 => r.server.control_denied = false,
                _ => r.server.sentinel = Sentinel::Absent,
            }
            let c = assemble(Host::Codex, "1.2.3", &cs(Host::Codex), Probed::Current(&r));
            let line = c.envcloak_server.unwrap_or_else(|| panic!("no line"));
            assert_eq!(line.probe, Outcome::Failed, "{strip}");
        }
        let mut r = full;
        r.server.outcome = Outcome::Skipped;
        r.server.control_ran = false;
        assert_eq!(r.server.supported(), Outcome::Skipped);
    }

    /// A case its probe did not run is named with the surface, in the
    /// report, `--json` and the cache, and never reads as passed.
    #[test]
    fn a_case_not_run_is_named_with_its_surface() {
        let mut r = record(Host::ClaudeCode, &all(Outcome::Passed));
        r.surfaces[2].skipped = vec![Case::AtMention];
        let c = assemble(
            Host::ClaudeCode,
            "1.2.3",
            &cs(Host::ClaudeCode),
            Probed::Current(&r),
        );
        let file = c
            .surface(Surface::FileRead)
            .cloned()
            .unwrap_or_else(|| panic!());
        assert_eq!(
            file.to_string(),
            "degraded (fails_open_on_timeout, workspace_untrusted; probe=passed, at_mention skipped)"
        );
        let text = serde_json::to_string(&file).unwrap_or_default();
        assert!(text.contains(r#""skipped":["at_mention"]"#), "{text}");
        assert_eq!(serde_json::from_str::<SurfaceState>(&text).ok(), Some(file));
        let back: ProbeRecord =
            serde_json::from_str(&serde_json::to_string(&r).unwrap_or_default())
                .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(back.surfaces[2].skipped, [Case::AtMention]);
        // No other surface names it.
        assert!(c.surfaces.iter().filter(|s| !s.skipped.is_empty()).count() == 1);
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
