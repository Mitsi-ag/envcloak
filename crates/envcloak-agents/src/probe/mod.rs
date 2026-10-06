//! Coverage probes (SPEC §7.1, §7.2 rule 2; M2 plan task M2-09): synthetic
//! activation and denial probes, run against a real agent host in a probe
//! home, whose results are the only way a surface reads `active`.
//!
//! [`run`] drives one host (Claude Code `-p`, Codex `exec`), with its
//! flags pinned per probe, against the scripted model ([`model`], the
//! program `envcloak-probe-model`), which records every request the host
//! sends. Every probe is paired with a control in the same probe home, so
//! a host that never reaches the model (a wrong base URL, an
//! authentication failure, a crash, an onboarding exit) fails the probe
//! through its control, never passes it ([`controls`]):
//!
//! - **prompt-to-model**: one session against one model: a benign prompt
//!   carrying a marker must reach the model, and its session be found by
//!   it in the host's store; the same session resumed with a prompt
//!   carrying a runtime-generated key-shaped token, which the host must
//!   report EnvCloak's hook blocked and which must never reach the model,
//!   in any form, anywhere the model recorded; and the session resumed
//!   again with a second marker, which must reach the model with the
//!   control's turn.
//! - **transcript**: the host's stores, where its environment and every
//!   layer of its settings place them (`coverage::Context::stores`), are
//!   swept after those runs, every file read whole and no link out of
//!   them, and every store known; the control's marker must be found by
//!   the sweep in its session's file, and only then does the absence of
//!   the blocked token count. A blocked token found there is
//!   `persists_blocked_prompt`. The prompt history only interactive
//!   sessions write is a case not run (`interactive_history skipped`).
//! - **file read** and **shell**: the host's own permission layer is opened
//!   for the probe (Claude Code `--permission-mode default` with
//!   `--allowedTools Bash,Read`; Codex `exec` with approval policy `never`
//!   in a `read-only` sandbox, which lets both commands run), so a denial
//!   must come from EnvCloak: a control (a README read, a printed marker)
//!   must reach the model, then the hook's case, a read of a `.env` and
//!   the printing of the environment, must be denied with EnvCloak's fixed
//!   marker (`[envcloak:env_file]`, `[envcloak:env_dump]`) in the host's
//!   next request, and nothing of the file or the environment reach it; a
//!   denial without the marker is a failed probe. The hook's case is a
//!   call EnvCloak's own host rules leave to the hook, on both hosts, so
//!   the marker can only be the hook's: Claude Code's `Read` of a `.env`
//!   outside the session's working directory (its `Read(**/.env*)` deny
//!   rule matches within it), Codex's `cat -- .env` and `env` (its
//!   `forbidden` rules match `cat .env` and `printenv`). The calls those
//!   rules cover are the rule's case: refused, by the rule (the host's
//!   refusal, named from a fixed list) or the hook. Claude Code's file
//!   read also covers an `@.env` mention, which no hook sees and only the
//!   `Read(**/.env*)` deny rule covers, best effort, against an
//!   `@README.md` control whose content must arrive; where the host does
//!   not expand `@` mentions under `-p`, that case is not run and is
//!   reported apart (`at_mention skipped`), never as passed.
//! - **MCP**: a fixture MCP server in the probe home with a benign tool
//!   (the control) and one that reads `.env` (the probe, denied with
//!   EnvCloak's marker).
//! - **output**: `envcloak run` of an emitter that prints the project's
//!   values, from the probe's directory (`cd` to the project first): its
//!   non-secret marker must reach the model, and no value in any form. This needs an approval from a terminal subject
//!   ([`Approver`]); with none, the probe is skipped
//!   (`probe_needs_terminal`).
//! - **EnvCloak's server**: the host's own shell, in its sandbox (Claude
//!   Code with `sandbox.enabled`; Codex `workspace-write` with its
//!   temporary directories excluded), writes in the project, is denied a
//!   write in the probe home, and prints a marker that must come back in
//!   its result (the witness that it ran: a missing file alone does not
//!   say so); then a `run_with_secrets` call with no bindings runs `touch`
//!   beside the denied write: the sentinel appearing is the evidence for
//!   `outside_host_sandbox` (D-03). Each piece is kept with the result.
//!
//! A refusal or a block in the host's own words counts as EnvCloak's rule's
//! or hook's only where no other's can give it ([`crate::coverage::ConfigSet`]'s
//! `foreign_read_deny` and `foreign_prompt_hook`, read in the probe's
//! directory). The result is kept under the identity the probe measured
//! ([`ProbeReport::record`]): the binary it ran and the probe context of
//! the directory the hosts ran in, each read before and after.
//!
//! A host version outside the scripted model's qualified table
//! ([`model::QUALIFIED`]) is not probed: every outcome is `not_qualified`.
//!
//! The probe home is the caller's: in CI an isolated test home with
//! EnvCloak installed by `envcloak agents install` (`crates/envcloak-e2e/
//! tests/probes.rs`); on a person's machine, [`local`]'s ([`home`], with a
//! probe-only daemon and the [`approve`] path, M2-28). The probe writes
//! only into it: its project's `README.md` and `.env` fixtures, a
//! sentinel directory and an MCP configuration file. Each run of the host
//! leads a session of its own on a terminal of its own ([`HostSession`]),
//! so nothing it does shares a session or a terminal with whoever approves
//! its requests (T9-3).

pub mod approve;
pub mod claude;
pub mod codex;
pub mod controls;
pub mod home;
pub mod local;
pub mod model;
pub mod qualify;
mod run;

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::coverage::{
    Case, Observed, Outcome, ProbeRecord, Reason, Sentinel, ServerObserved, Surface,
};
use crate::hook::Host;

pub use run::{HostSession, run, run_surfaces};

/// The host a probe drives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeHost {
    pub host: Host,
    /// Its executable.
    pub exe: PathBuf,
    /// The version it reports.
    pub version: String,
}

/// Flags the probe home adds to every run of its host, after the probe's
/// own, each recorded with the result: Codex's
/// `--dangerously-bypass-hook-trust` in a probe home, standing for the
/// person's trust in `/hooks` (D-13; never written into a configuration).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFlags {
    pub args: Vec<String>,
}

/// Approves the requests the output and sentinel probes make, from a
/// terminal subject of its own (never the host's: T9-3), against the probe
/// home's daemon, with every proof rule kept.
pub trait Approver: Sync {
    /// Waits for the host's next request to be pending, and approves it,
    /// until `deadline` or until `stop` is set (the host's run ended).
    ///
    /// # Errors
    /// When no request was approved; the text names no value.
    fn approve(&self, deadline: Instant, stop: &AtomicBool) -> Result<(), String>;
}

/// What the output probe runs: a command in a project whose manifest binds
/// `values`, which prints `marker` (non-secret) and the values.
pub struct OutputFixture {
    /// The project (its manifest binds the values).
    pub project: PathBuf,
    /// The command `envcloak run --` runs there.
    pub command: Vec<String>,
    /// What the command prints that is not a value: the control.
    pub marker: String,
    /// The values bound, each looked for in every form.
    pub values: Vec<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for OutputFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutputFixture")
            .field("project", &self.project)
            .field("command_words", &self.command.len())
            .field("values", &self.values.len())
            .finish_non_exhaustive()
    }
}

/// Where a probe runs and what it may use.
pub struct ProbeHome<'a> {
    /// A directory of the probe's own (its MCP configuration goes there).
    pub root: PathBuf,
    /// `HOME`.
    pub home: PathBuf,
    /// The host's environment: cleared, then exactly this (`HOME`, every
    /// `XDG_*`, `TMPDIR`, `CODEX_HOME`, `CLAUDE_CODE_TMPDIR`, `PATH`,
    /// ...); the probe adds the model's settings.
    pub env: Vec<(OsString, OsString)>,
    /// The directory the hosts run in; the probe writes its `README.md`
    /// and `.env` fixtures there.
    pub project: PathBuf,
    /// `envcloak-probe-model`.
    pub model_exe: PathBuf,
    /// The `envcloak` the hooks and the output probe run.
    pub envcloak: PathBuf,
    /// A stdio MCP server with the tools `echo {text, more}` and
    /// `read_file {path}`; without one the MCP probe is skipped.
    pub mcp_fixture: Option<PathBuf>,
    /// A project whose manifest binds nothing, for the sentinel probe.
    pub sentinel_project: Option<PathBuf>,
    pub output: Option<OutputFixture>,
    pub approver: Option<&'a dyn Approver>,
    /// How long one host run may take.
    pub run_limit: Duration,
}

impl fmt::Debug for ProbeHome<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeHome")
            .field("root", &self.root)
            .field("home", &self.home)
            .field(
                "env_names",
                &self.env.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .field("project", &self.project)
            .field("mcp_fixture", &self.mcp_fixture.is_some())
            .field("output", &self.output)
            .field("approver", &self.approver.is_some())
            .finish_non_exhaustive()
    }
}

/// One check a probe made: a control or the probe itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Check {
    /// What it checked (fixed text).
    pub name: &'static str,
    /// A control (the host reached the model, ran the benign call) rather
    /// than the probe.
    pub control: bool,
    pub passed: bool,
    /// Why it failed (fixed text), or `""`; for a passed check of what a
    /// host refused, what refused it (fixed text).
    pub why: &'static str,
}

/// One surface's probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceProbe {
    pub surface: Surface,
    pub outcome: Outcome,
    pub checks: Vec<Check>,
    /// The transcript probe found the blocked prompt in the host's stores.
    pub persisted: bool,
    /// Why it was skipped, when it was.
    pub why: Vec<Reason>,
    /// The cases of it that were not run, while the rest was: its outcome
    /// is the rest's, and these are reported apart, never as passed.
    pub skipped: Vec<Case>,
}

/// The sentinel probe for EnvCloak's server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerProbe {
    pub outcome: Outcome,
    pub sentinel: Sentinel,
    /// The host's own shell ran the control: the marker it prints after
    /// its writes came back in its result (Codex F-133: a missing file
    /// alone does not say the shell ran).
    pub control_ran: bool,
    /// That shell made its write where its sandbox lets it.
    pub allowed_write: bool,
    /// That shell was denied the write beside the sentinel's.
    pub control_denied: bool,
    pub checks: Vec<Check>,
}

/// What one host run did, value-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {
    /// Which probe it was for.
    pub name: &'static str,
    /// The flags it pinned (never the prompt).
    pub flags: Vec<String>,
    /// The host's exit code; `None` when a signal ended it or the probe
    /// stopped it at its limit.
    pub exit: Option<i32>,
    pub timed_out: bool,
    /// Requests the model recorded.
    pub requests: usize,
    /// The model's run was clean: complete, and nothing it did not serve.
    pub clean: bool,
    pub elapsed: Duration,
    /// Whether an approval was given during the run, when one was asked
    /// for.
    pub approved: Option<bool>,
}

/// A probe's results for one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    pub host: Host,
    pub version: String,
    pub surfaces: Vec<SurfaceProbe>,
    pub server: ServerProbe,
    pub runs: Vec<RunSummary>,
    /// The flags the probe home added ([`HostFlags`]).
    pub flags: Vec<String>,
    /// The SHA-256 of the host binary the probe ran (its executable,
    /// resolved), read before and after: empty when it could not be read
    /// or changed meanwhile.
    pub exe_sha256: String,
    /// The fingerprint of the probe context the hosts ran in
    /// (`coverage::ConfigSet::fingerprint` for the probe's directory and
    /// environment, with the `envcloak` the probe ran), read before and
    /// after: empty when it could not be read whole or changed meanwhile.
    pub config_digest: String,
    /// The probe context's shape (`coverage::ConfigSet::shape`, relative
    /// to the probe's `HOME`), read before and after: what a result
    /// measured in a probe home can be compared with the person's
    /// configuration by (M2-28). Empty as `config_digest` is.
    pub config_shape: String,
}

impl ProbeReport {
    /// The probe of `surface`.
    pub fn surface(&self, surface: Surface) -> Option<&SurfaceProbe> {
        self.surfaces.iter().find(|s| s.surface == surface)
    }

    /// What the cache keeps of this report, under the identity it
    /// measured: the binary it ran and the probe context it ran in (Codex
    /// review of M2-09: an identity the caller passed could be another
    /// binary's or another directory's). An identity not read is kept
    /// empty, which no lookup matches.
    pub fn record(&self) -> ProbeRecord {
        ProbeRecord {
            host: self.host.id().to_owned(),
            exe_sha256: self.exe_sha256.clone(),
            version: self.version.clone(),
            config_digest: self.config_digest.clone(),
            os: std::env::consts::OS.to_owned(),
            surfaces: self
                .surfaces
                .iter()
                .map(|s| Observed {
                    surface: s.surface,
                    outcome: s.outcome,
                    persisted: s.persisted,
                    why: s.why.clone(),
                    skipped: s.skipped.clone(),
                })
                .collect(),
            server: ServerObserved {
                outcome: self.server.outcome,
                sentinel: self.server.sentinel,
                control_ran: self.server.control_ran,
                allowed_write: self.server.allowed_write,
                control_denied: self.server.control_denied,
            },
            flags: self.flags.clone(),
        }
    }
}
