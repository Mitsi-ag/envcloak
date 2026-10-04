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
//! - **prompt-to-model**: a benign prompt carrying a marker must reach the
//!   model; a prompt carrying a runtime-generated key-shaped token must
//!   never reach it, in any form, anywhere the model recorded.
//! - **transcript**: the host's stores (`Locations::transcript_sources`)
//!   are swept after those two runs; the control's marker must be found
//!   there first, and only then does the absence of the blocked token
//!   count. A blocked token found there is `persists_blocked_prompt`.
//! - **file read** and **shell**: the host's own permission layer is opened
//!   for the probe (Claude Code `--permission-mode default` with
//!   `--allowedTools Bash,Read`; Codex `exec` with approval policy `never`
//!   in a `read-only` sandbox, which lets both commands run), so a denial
//!   must come from EnvCloak: a control (a README read, a printed marker)
//!   must reach the model, then the read of `.env` and the printing of the
//!   environment must be denied with EnvCloak's fixed marker
//!   (`[envcloak:env_file]`, `[envcloak:env_dump]`) in the host's next
//!   request, and nothing of the file or the environment reach it; a
//!   denial without the marker is a failed probe. Claude Code's file read
//!   also covers an `@.env` mention, which no hook sees and only the
//!   `Read(**/.env*)` deny rule covers, best effort, against an
//!   `@README.md` control whose content must arrive; where the host does
//!   not expand `@` mentions under `-p`, that case is skipped, not failed.
//! - **MCP**: a fixture MCP server in the probe home with a benign tool
//!   (the control) and one that reads `.env` (the probe, denied with
//!   EnvCloak's marker).
//! - **output**: `envcloak run` of an emitter that prints the project's
//!   values: its non-secret marker must reach the model, and no value in
//!   any form. This needs an approval from a terminal subject
//!   ([`Approver`]); with none, the probe is skipped
//!   (`probe_needs_terminal`).
//! - **EnvCloak's server**: a `run_with_secrets` call with no bindings runs
//!   `touch` on a path in the probe home that the host's own sandbox
//!   denies (Claude Code with `sandbox.enabled`; Codex `workspace-write`
//!   with its temporary directories excluded), after a control shell
//!   command shows that denial: the sentinel appearing is the evidence for
//!   `outside_host_sandbox` (D-03).
//!
//! A host version outside the scripted model's qualified table
//! ([`model::QUALIFIED`]) is not probed: every outcome is `not_qualified`.
//!
//! The probe home is the caller's: in CI an isolated test home with
//! EnvCloak installed by `envcloak agents install` (`crates/envcloak-e2e/
//! tests/probes.rs`); on a person's machine, M2-28's. The probe writes
//! only into it: its project's `README.md` and `.env` fixtures, a
//! sentinel directory and an MCP configuration file.

pub mod claude;
pub mod codex;
pub mod controls;
pub mod model;
mod run;

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::coverage::{Observed, Outcome, ProbeRecord, Reason, Sentinel, ServerObserved, Surface};
use crate::hook::Host;

pub use run::{run, run_surfaces};

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
    /// Why it failed (fixed text), or `""`.
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
}

/// The sentinel probe for EnvCloak's server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerProbe {
    pub outcome: Outcome,
    pub sentinel: Sentinel,
    /// The host's own shell was denied the control write.
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
}

impl ProbeReport {
    /// The probe of `surface`.
    pub fn surface(&self, surface: Surface) -> Option<&SurfaceProbe> {
        self.surfaces.iter().find(|s| s.surface == surface)
    }

    /// What the cache keeps of this report, for the host binary whose
    /// SHA-256 is `exe_sha256` and the configuration whose digest is
    /// `config_digest`.
    pub fn record(&self, exe_sha256: &str, config_digest: &str) -> ProbeRecord {
        ProbeRecord {
            host: self.host.id().to_owned(),
            exe_sha256: exe_sha256.to_owned(),
            version: self.version.clone(),
            config_digest: config_digest.to_owned(),
            os: std::env::consts::OS.to_owned(),
            surfaces: self
                .surfaces
                .iter()
                .map(|s| Observed {
                    surface: s.surface,
                    outcome: s.outcome,
                    persisted: s.persisted,
                    why: s.why.clone(),
                })
                .collect(),
            server: ServerObserved {
                outcome: self.server.outcome,
                sentinel: self.server.sentinel,
                control_denied: self.server.control_denied,
            },
            flags: self.flags.clone(),
        }
    }
}
