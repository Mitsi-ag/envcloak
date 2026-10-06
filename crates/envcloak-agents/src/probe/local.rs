//! Probes on the person's own machine (M2 plan task M2-28): what
//! `envcloak agents status --probe` runs, so that the probes of
//! [`super::run`] measure the person's installed host without using or
//! touching anything of the person's.
//!
//! For one host ([`probe_host`]):
//!
//! 1. A host version outside the scripted model's qualification table is
//!    not probed at all ([`super::qualify`]): every outcome is
//!    `not_qualified`, and nothing is started or made.
//! 2. A probe home of its own ([`super::home::ProbeHome`]): a short private
//!    directory under `/tmp`, its environment cleared and rebuilt, its
//!    socket path computed with `envcloak-ipc`'s resolver and refused unless
//!    it fits `sun_path` and is not the person's.
//! 3. A probe-only daemon ([`ProbeDaemon`]): `envcloakd --foreground`,
//!    started by absolute path (the one beside this `envcloak`) with the
//!    probe home's environment, in a session of its own on a terminal of its
//!    own whose other side only this process holds: however this process
//!    ends, `kill -9` included, the kernel hangs that terminal up and the
//!    daemon gets SIGHUP, locks and exits (envcloak-sys
//!    `new_session_on_spawn`). Its vault is a throwaway one, created here
//!    with a generated passphrase and a generated Recovery Kit, the kit
//!    dropped and the passphrase held only in this process's wiped memory;
//!    its one item holds a generated value.
//! 4. EnvCloak installed for the host in the probe home by this build's
//!    own installer (`envcloak agents install --agent <id> --yes`, run with
//!    the probe home's environment, so its backups go to the probe daemon):
//!    EnvCloak's installed configuration, as it installs it, and never the
//!    person's agent credentials or settings (the scripted model needs
//!    none). Codex on macOS gets the socket allowance's consent, as in CI.
//!    What was measured there is kept for the person's configuration only
//!    when theirs has the same shape ([`keep_record`]).
//! 5. The probes of every surface and of EnvCloak's server
//!    ([`super::run_surfaces`]), the host started by the path the person's
//!    `PATH` gives it, each run in a session of its own on a terminal of its
//!    own ([`super::HostSession`]), with Codex's labelled hook-trust bypass
//!    standing for the person's trust in `/hooks` (D-13), as in CI.
//! 6. Everything stopped, and the probe home removed.
//!
//! **The approval path.** The output and sentinel probes make requests a
//! person must approve, with every proof rule kept (SPEC §10b; gate 23):
//! the approver ([`super::approve`]) is `envcloak approve <id> --once`, run
//! by this process in its own session and on its own terminal (the
//! person's), with the probe passphrase on a descriptor, against the probe
//! daemon only. The host runs in a session and on a terminal of its own, so
//! that approval is never one from the host's session or terminal (T9-3,
//! F-70). Before any probe, this process asks the probe daemon for the
//! probe item's target, a read the daemon serves only to a caller that may
//! give a proof: when it refuses (this process is an agent's, or has no
//! controlling terminal, an agent having run `agents status --probe`), no
//! approval is attempted, and the output and sentinel probes are skipped
//! with `probe_needs_terminal`.

use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use envcloak_core::{RecoveryKit, SecretBytes, suggest_passphrase};
use envcloak_ipc::proto::{AddParams, ErrorKind};
use envcloak_ipc::{Client, ClientError, RunPaths, WireSecret};
use zeroize::Zeroizing;

use super::approve::ProbeApprover;
use super::home::{ProbeError, ProbeHome as LocalHome};
use super::qualify::{Qualification, qualify};
use super::{HostFlags, OutputFixture, ProbeHome, ProbeHost, ProbeReport, ServerProbe};
use crate::coverage::{Outcome, Sentinel, Surface};
use crate::hook::Host;

/// How long one host run may take.
pub const RUN_LIMIT: Duration = Duration::from_secs(180);
/// How long the probe daemon may take to listen.
const DAEMON_START: Duration = Duration::from_secs(60);
/// How long the probe daemon may take to stop once asked.
const DAEMON_STOP: Duration = Duration::from_secs(20);
/// How long `envcloak agents install` may take in the probe home.
const INSTALL_LIMIT: Duration = Duration::from_secs(120);
/// The Argon2id memory of the throwaway vault (the least `vault create`
/// takes in CI too).
const KDF_MEMORY_KIB: u32 = 64 * 1024;
/// The most of the probe daemon's log kept.
const MAX_LOG: usize = 64 * 1024;
/// The probe vault's item, and the variable the output project binds it to.
pub const PROBE_SLUG: &str = "ecprobe/output";
pub const PROBE_ENV: &str = "ECPROBE_SECRET";

/// Why a probe on this machine could not be set up. Value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalError {
    /// The probe home could not be made.
    Home(ProbeError),
    /// The probe daemon did not start, or stopped.
    Daemon,
    /// The throwaway vault could not be created.
    Vault,
    /// EnvCloak could not be installed for the host in the probe home.
    Install,
    /// The probe's projects could not be written.
    Fixtures,
    /// The person's agent catalog extensions could not be given to the
    /// probe daemon.
    Catalog,
    /// A system or managed configuration of the host's is on this machine
    /// ([`inherited_configuration`]), which the host would load in the
    /// probe home too.
    Inherited,
}

impl LocalError {
    /// What it means, value-free.
    pub fn message(self) -> &'static str {
        match self {
            LocalError::Home(e) => e.message(),
            LocalError::Daemon => "the probe's own daemon did not start",
            LocalError::Vault => "the probe's throwaway vault could not be created",
            LocalError::Install => "EnvCloak could not be installed for the host in the probe home",
            LocalError::Fixtures => "the probe's projects could not be written in the probe home",
            LocalError::Inherited => {
                "a system or managed configuration for this host is on this machine (its system \
                 directory, managed settings or a device profile), which the host loads whatever \
                 its home: it could run that configuration's hooks and servers and write where it \
                 says, outside the probe home, so the host was not probed"
            }
            LocalError::Catalog => {
                "your agent catalog extensions (agents.d) could not be given to the probe's daemon, \
                 so it could not tell your agents as your daemon does"
            }
        }
    }
}

impl From<ProbeError> for LocalError {
    fn from(e: ProbeError) -> Self {
        LocalError::Home(e)
    }
}

/// What a probe on this machine uses.
#[derive(Debug, Clone)]
pub struct LocalOptions {
    /// This `envcloak`, resolved: the hooks and the output probe run it.
    pub envcloak: PathBuf,
    /// The `envcloakd` beside it.
    pub envcloakd: PathBuf,
    /// The `envcloak-probe-model` beside it.
    pub model_exe: PathBuf,
    /// A fixture MCP server, when one is installed beside it.
    pub mcp_fixture: Option<PathBuf>,
    /// `PATH` in the probe home: the directories the host and EnvCloak are
    /// found in, then the person's absolute `PATH` entries.
    pub path: OsString,
    /// The catalog's agent markers set in this process's environment, with
    /// their values: the approver claims them too, as this process does.
    pub markers: Vec<(OsString, OsString)>,
    /// Their names, as this process claims them to the probe daemon.
    pub claims: Vec<String>,
    /// Where the probe home is made ([`super::home::TMP`]).
    pub tmp: PathBuf,
    /// The person's own daemon socket, which the probe's must not be.
    pub person_socket: Option<PathBuf>,
    /// The person's EnvCloak data directory, whose agent catalog
    /// extensions (`agents.d`) the probe daemon is given, read-only.
    pub person_data: PathBuf,
    /// How long one host run may take.
    pub run_limit: Duration,
}

/// A probe run on this machine.
#[derive(Debug)]
pub struct LocalRun {
    pub report: ProbeReport,
    pub qualification: Qualification,
    /// Approvals the probe's approver gave (each `--once`).
    pub approvals: usize,
    /// The probe daemon refused this process a proof-gated read, so no
    /// approval was attempted (`probe_needs_terminal`).
    pub needs_terminal: bool,
    /// The probe home was removed at the end.
    pub home_removed: bool,
}

/// Probes `host` on this machine as the module documentation says.
///
/// # Errors
/// When the probe home, the probe daemon, its vault, EnvCloak's install
/// there or the probe's projects could not be set up: nothing was probed,
/// and the probe home is removed.
pub fn probe_host(host: &ProbeHost, opts: &LocalOptions) -> Result<LocalRun, LocalError> {
    let qualification = qualify(host.host, &host.version);
    if !qualification.is_qualified() {
        return Ok(LocalRun {
            report: not_qualified(host),
            qualification,
            approvals: 0,
            needs_terminal: false,
            home_removed: true,
        });
    }
    let home = LocalHome::create_in(&opts.tmp, opts.person_socket.as_deref())?;
    let mut env = home.env();
    env.push(("PATH".into(), opts.path.clone()));
    let run = (|| {
        copy_agent_extensions(&opts.person_data, &home.data_dir()?)?;
        let mut daemon = ProbeDaemon::start(&opts.envcloakd, &home, &env)?;
        daemon.create_vault()?;
        install(host.host, &opts.envcloak, &home, &env)?;
        let fx = Fixtures::write(&home, &mut daemon)?;
        let may_approve = daemon.may_approve(&opts.claims);
        let approver = ProbeApprover::new(
            &daemon,
            opts.envcloak.clone(),
            opts.markers.clone(),
            opts.claims.clone(),
        );
        let run_home = ProbeHome {
            root: home.root().to_path_buf(),
            home: home.home(),
            env: env.clone(),
            project: fx.probe.clone(),
            model_exe: opts.model_exe.clone(),
            envcloak: opts.envcloak.clone(),
            mcp_fixture: opts.mcp_fixture.clone(),
            sentinel_project: Some(fx.sentinel.clone()),
            output: Some(OutputFixture {
                project: fx.output.clone(),
                command: vec!["./emit".to_owned()],
                marker: fx.marker.clone(),
                values: vec![Zeroizing::new(fx.value.as_bytes().to_vec())],
            }),
            approver: may_approve.then_some(&approver as &dyn super::Approver),
            run_limit: opts.run_limit,
        };
        let report =
            super::run_surfaces(host, &run_home, &host_flags(host.host), &Surface::ALL, true);
        drop(run_home);
        let approvals = approver.given();
        drop(approver);
        daemon.stop();
        Ok(LocalRun {
            report,
            qualification: Qualification::Qualified,
            approvals,
            needs_terminal: !may_approve,
            home_removed: false,
        })
    })();
    let removed = home.remove().is_ok();
    run.map(|mut r: LocalRun| {
        r.home_removed = removed;
        r
    })
}

/// The flags the probe home adds to every run of `host`: Codex's trust
/// bypass, standing for the person's trust in `/hooks` (D-13: labelled,
/// never written into a configuration), as in CI.
pub fn host_flags(host: Host) -> HostFlags {
    HostFlags {
        args: match host {
            Host::Codex => vec!["--dangerously-bypass-hook-trust".to_owned()],
            Host::ClaudeCode => Vec::new(),
        },
    }
}

/// The report of a host whose version the probe is not qualified for:
/// every outcome `not_qualified`, nothing run, the binary and context
/// left for the caller to identify.
pub fn not_qualified(host: &ProbeHost) -> ProbeReport {
    ProbeReport {
        host: host.host,
        version: host.version.clone(),
        surfaces: Surface::ALL
            .into_iter()
            .map(|surface| super::SurfaceProbe {
                surface,
                outcome: Outcome::NotQualified,
                checks: Vec::new(),
                persisted: false,
                why: Vec::new(),
                skipped: Vec::new(),
            })
            .collect(),
        server: ServerProbe {
            outcome: Outcome::NotQualified,
            sentinel: Sentinel::NotRun,
            control_ran: false,
            allowed_write: false,
            control_denied: false,
            checks: Vec::new(),
        },
        runs: Vec::new(),
        flags: Vec::new(),
        exe_sha256: String::new(),
        config_digest: String::new(),
        config_shape: String::new(),
    }
}

/// Why a probe's result is not kept for the person's host and
/// configuration. Value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotKept {
    /// The host binary on the person's `PATH` could not be read whole.
    BinaryNotRead,
    /// The person's configuration could not be identified whole
    /// (`coverage::ConfigSet::fingerprint`).
    ConfigurationNotRead,
    /// The host binary or the person's configuration changed while the
    /// probe ran.
    ChangedWhileProbing,
    /// The probe could not identify what it ran, or in what.
    ProbeNotIdentified,
    /// The person's hooks run another `envcloak` than the one that probed.
    AnotherEnvcloak,
    /// The person's configuration is not the one the probe measured: its
    /// shape (`coverage::ConfigSet::shape`) differs from the probe home's,
    /// EnvCloak's entries, the facts the probes act out or the host's
    /// stores being other than this build installs and the probe ran with.
    ConfigurationDiffers,
}

impl NotKept {
    /// Why, value-free.
    pub fn message(self) -> &'static str {
        match self {
            NotKept::BinaryNotRead => "the host's binary could not be read whole",
            NotKept::ConfigurationNotRead => {
                "your configuration for this host could not be read whole"
            }
            NotKept::ChangedWhileProbing => {
                "the host's binary or your configuration changed while the probe ran"
            }
            NotKept::ProbeNotIdentified => {
                "the probe could not identify the binary it ran, or its probe home"
            }
            NotKept::AnotherEnvcloak => {
                "your hooks run another envcloak than this one, which the probe ran: run the \
                 probe with that one, or install EnvCloak again with this one"
            }
            NotKept::ConfigurationDiffers => {
                "your configuration for this host is not the one the probe ran with (EnvCloak's \
                 hooks or server entry, a setting the probes rest on, or where the host keeps \
                 transcripts differs from EnvCloak as this envcloak installs it): install \
                 EnvCloak again with this envcloak, then run the probe again"
            }
        }
    }
}

/// The person's host and configuration, as `agents status` identifies
/// them, read before and after the probe.
#[derive(Debug, Clone, Copy)]
pub struct PersonIdentity<'a> {
    /// The SHA-256 of the host binary the person's `PATH` leads to,
    /// resolved (empty when it could not be read).
    pub exe_sha256: &'a str,
    /// `coverage::ConfigSet::fingerprint` of the person's configuration
    /// for the working directory, with this `envcloak`, before the probe.
    pub before: Option<&'a str>,
    /// The same, after.
    pub after: Option<&'a str>,
    /// The programs the person's EnvCloak hooks run, by their SHA-256.
    pub programs: &'a [crate::coverage::ProgramSeen],
    /// The SHA-256 of the `envcloak` that probed.
    pub envcloak_sha256: &'a str,
    /// `coverage::ConfigSet::shape` of the person's configuration, relative
    /// to their `HOME`, with this `envcloak`.
    pub shape: Option<&'a str>,
}

/// The record the cache keeps for `run`, under the person's identity, or
/// why it is not kept (L-09: a result is current only for what it
/// measured). Kept under the person's host binary and configuration
/// fingerprint: the probe measured that binary, with EnvCloak installed as
/// this build installs it, run by this `envcloak`; what the person's own
/// files switch off is applied at display from those files (the
/// fingerprint's facts). So the record is kept only when the binary the
/// probe ran is the person's, neither it nor the configuration changed
/// meanwhile, the person's hooks run the same `envcloak`, and the person's
/// configuration has the probe home's shape (`coverage::ConfigSet::shape`:
/// EnvCloak's hook and server entries as they are written, the facts the
/// probes act out, the stores; Codex review of M2-28, a result measured on
/// a fresh install was credited to a configuration that differed from it).
/// A host version that is not qualified is kept as `not_qualified` under
/// the same identity, so `agents status` says why it has no probe result:
/// that outcome rests on the version alone.
///
/// # Errors
/// See [`NotKept`].
pub fn keep_record(
    run: &LocalRun,
    person: &PersonIdentity<'_>,
) -> Result<crate::coverage::ProbeRecord, NotKept> {
    if person.exe_sha256.is_empty() {
        return Err(NotKept::BinaryNotRead);
    }
    let (Some(before), Some(after)) = (person.before, person.after) else {
        return Err(NotKept::ConfigurationNotRead);
    };
    if before.is_empty() || after.is_empty() {
        return Err(NotKept::ConfigurationNotRead);
    }
    if before != after {
        return Err(NotKept::ChangedWhileProbing);
    }
    if run.qualification.is_qualified() {
        if run.report.exe_sha256.is_empty()
            || run.report.config_digest.is_empty()
            || run.report.config_shape.is_empty()
        {
            return Err(NotKept::ProbeNotIdentified);
        }
        if run.report.exe_sha256 != person.exe_sha256 {
            return Err(NotKept::ChangedWhileProbing);
        }
        if person.envcloak_sha256.is_empty() {
            return Err(NotKept::ProbeNotIdentified);
        }
        let other = person
            .programs
            .iter()
            .filter_map(|p| p.sha256.as_deref())
            .any(|s| s != person.envcloak_sha256);
        if other {
            return Err(NotKept::AnotherEnvcloak);
        }
        match person.shape {
            None | Some("") => return Err(NotKept::ConfigurationNotRead),
            Some(s) if s != run.report.config_shape => {
                return Err(NotKept::ConfigurationDiffers);
            }
            Some(_) => {}
        }
    }
    let mut record = run.report.record();
    record.exe_sha256 = person.exe_sha256.to_owned();
    record.config_digest = before.to_owned();
    Ok(record)
}

/// The configuration `host` loads whatever its home and environment say,
/// present on this machine: Claude Code's managed settings, their drop-ins
/// and the organization's `managed-mcp.json` in `claude_managed`, and its
/// device profiles; Codex's system directory (`config.toml`, `hooks.json`,
/// `managed_config.toml`, `requirements.toml`) and its device profiles. A
/// probe home cannot keep the host from these (Codex review of M2-28: a
/// managed `log_dir` or `sqlite_home` given as an absolute path sends the
/// probe's writes into the person's files, and a managed hook or server
/// runs their real integration), so a host with any is not probed
/// ([`LocalError::Inherited`]). A path whose state cannot be read, or a
/// device profile folder that cannot be listed, counts as present.
pub fn inherited_configuration(
    host: Host,
    l: &crate::locations::Locations,
    claude_managed: &Path,
) -> Vec<PathBuf> {
    // Absent: nothing there, or a file where a folder of the path would
    // be (a device profile entry that is a file, not a user's folder).
    let present = |p: &Path| match std::fs::symlink_metadata(p) {
        Ok(_) => true,
        Err(e) => {
            e.kind() != std::io::ErrorKind::NotFound && e.raw_os_error() != Some(libc::ENOTDIR)
        }
    };
    let (mut candidates, profiles) = match host {
        Host::ClaudeCode => (
            vec![
                claude_managed.join("managed-settings.json"),
                claude_managed.join("managed-settings.d"),
                claude_managed.join("managed-mcp.json"),
            ],
            l.claude_managed_preferences(),
        ),
        Host::Codex => (
            vec![
                l.codex_system_config(),
                l.codex_system_hooks(),
                l.codex_managed_config(),
                l.codex_requirements(),
            ],
            l.codex_managed_preferences(),
        ),
    };
    match profiles {
        Ok(ps) => candidates.extend(ps),
        // Not listed: what it holds is not known.
        Err(_) => return vec![PathBuf::from("/Library/Managed Preferences")],
    }
    candidates.into_iter().filter(|p| present(p)).collect()
}

/// The programs a probe on this machine runs besides `envcloak`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePrograms {
    pub envcloakd: PathBuf,
    pub model: PathBuf,
    pub mcp: PathBuf,
}

/// The name of the probe's MCP server program.
pub const MCP_PROGRAM: &str = "envcloak-probe-mcp";
/// The name of the scripted model's program.
pub const MODEL_PROGRAM: &str = "envcloak-probe-model";

/// Finds what a probe runs, for `me`, this `envcloak` resolved: the
/// scripted model and the probe's MCP server beside it, and `envcloakd`
/// beside it or, when `me` is the CLI of the macOS app
/// (`<app>/Contents/MacOS/envcloak`), in the app's helper
/// (`<app>/Contents/Helpers/EnvCloakAgent.app/Contents/MacOS/envcloakd`,
/// where `scripts/macos/build-app.sh` puts it; the verifier's and Codex's
/// reviews of M2-28: `--probe` from the app could never find it). Each
/// must be an executable regular file. All three are needed: a probe
/// without its MCP server would leave that surface unmeasured, and
/// `--probe` says so rather than report the others as the whole.
///
/// # Errors
/// What is missing, value-free.
pub fn locate_programs(me: &Path) -> Result<ProbePrograms, &'static str> {
    use std::os::unix::fs::PermissionsExt as _;
    let executable = |p: &Path| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    let dir = me
        .parent()
        .ok_or("the path of this envcloak could not be read")?;
    let helper = dir
        .parent()
        .filter(|contents| {
            dir.file_name() == Some(std::ffi::OsStr::new("MacOS"))
                && contents.file_name() == Some(std::ffi::OsStr::new("Contents"))
        })
        .map(|contents| {
            contents
                .join("Helpers")
                .join("EnvCloakAgent.app")
                .join("Contents")
                .join("MacOS")
                .join("envcloakd")
        });
    let envcloakd = [Some(dir.join("envcloakd")), helper]
        .into_iter()
        .flatten()
        .find(|p| executable(p))
        .ok_or(
            "the probes need envcloakd, which is neither beside this envcloak nor in its app's \
             helper; nothing was probed",
        )?;
    let model = dir.join(MODEL_PROGRAM);
    let mcp = dir.join(MCP_PROGRAM);
    if !executable(&model) || !executable(&mcp) {
        return Err(
            "the probes need envcloak-probe-model and envcloak-probe-mcp installed beside this \
             envcloak (a source build has them in its target directory; the macOS app ships \
             them beside its CLI); nothing was probed",
        );
    }
    Ok(ProbePrograms {
        envcloakd,
        model,
        mcp,
    })
}

/// Gives the probe daemon the person's agent catalog extensions: each
/// file of `<person_data>/agents.d` that the person's own daemon reads
/// (`AgentCatalog::extension_files`, with every check its `load` applies:
/// no link followed, the directory and each file the person's and written
/// by no one else, the size and count limits) is written, byte for byte,
/// into `<probe_data>/agents.d` (mode 0700, each file 0600). The probe
/// daemon then classifies the processes that ask it for an approval as the
/// person's daemon would: an agent only an extension names is an agent
/// there too, so `agents status --probe` run by it gives
/// `probe_needs_terminal` and no grant (the verifier's review of M2-28:
/// with the builtin catalog alone, the probe daemon judged it a terminal
/// and approved). Nothing of the person's is written; a file their daemon
/// skips is not copied.
///
/// # Errors
/// [`LocalError::Catalog`] when the directory or a file cannot be made.
pub fn copy_agent_extensions(person_data: &Path, probe_data: &Path) -> Result<(), LocalError> {
    let read = envcloak_policy::AgentCatalog::extension_files(person_data);
    let files: Vec<_> = read
        .files
        .into_iter()
        .filter_map(|(name, bytes)| bytes.ok().map(|b| (name, b)))
        .collect();
    if read.directory.is_some() || files.is_empty() {
        return Ok(());
    }
    let fail = |_| LocalError::Catalog;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(probe_data)
        .map_err(fail)?;
    let dir = probe_data.join(envcloak_policy::AGENTS_DIR);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(fail)?;
    for (name, bytes) in files {
        new_file(&dir.join(name), &bytes, 0o600).map_err(|_| LocalError::Catalog)?;
    }
    Ok(())
}

/// `envcloak agents install --agent <host> --yes --json` in the probe home.
fn install(
    host: Host,
    envcloak: &Path,
    home: &LocalHome,
    env: &[(OsString, OsString)],
) -> Result<(), LocalError> {
    let mut cmd = Command::new(envcloak);
    cmd.env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .args(["agents", "install", "--agent", host.id(), "--yes", "--json"])
        .current_dir(home.home())
        .stdin(Stdio::null())
        // Its report is the probe home's, never part of this one's.
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if cfg!(target_os = "macos") && host == Host::Codex {
        cmd.arg("--consent-sandbox-sockets");
    }
    match crate::detect::run_bounded(&mut cmd, INSTALL_LIMIT, 1 << 20) {
        Ok(out) if out.status.success() => Ok(()),
        _ => Err(LocalError::Install),
    }
}

/// The probe's projects: the directory the hosts run in (`~/probe`), the
/// output project (a manifest binding the probe item, and an emitter that
/// prints a marker and the value as it is, in base64 and in hexadecimal),
/// and the sentinel project (a manifest that binds nothing).
struct Fixtures {
    probe: PathBuf,
    output: PathBuf,
    sentinel: PathBuf,
    marker: String,
    value: Zeroizing<String>,
}

impl Fixtures {
    fn write(home: &LocalHome, daemon: &mut ProbeDaemon) -> Result<Fixtures, LocalError> {
        let fail = |_| LocalError::Fixtures;
        let probe = home.home().join("probe");
        let output = home.root().join("acme");
        let sentinel = home.root().join("sentinel");
        for d in [&probe, &output, &sentinel] {
            std::fs::create_dir(d).map_err(fail)?;
        }
        let marker = super::controls::marker("emit").map_err(fail)?;
        let mut rnd = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *rnd).map_err(|_| LocalError::Fixtures)?;
        let value = Zeroizing::new(format!("ecprobe-{}", crate::coverage::hex(&*rnd)));
        daemon.add_item(&value)?;
        new_file(
            &output.join("envcloak.toml"),
            format!(
                "[project]\nname = \"probe-output\"\n\n[env]\n{PROBE_ENV} = \"{PROBE_SLUG}\"\n"
            )
            .as_bytes(),
            0o600,
        )?;
        let (a, b) = super::controls::halves(&marker);
        new_file(
            &output.join("emit"),
            format!(
                "#!/bin/sh\nprintf '%s%s\\n' '{a}' '{b}'\nprintf '%s\\n' \"${PROBE_ENV}\"\n\
                 printf '%s' \"${PROBE_ENV}\" | base64\nprintf '%s' \"${PROBE_ENV}\" | od -An \
                 -tx1 | tr -d ' \\n'\necho\n"
            )
            .as_bytes(),
            0o700,
        )?;
        new_file(
            &sentinel.join("envcloak.toml"),
            b"[project]\nname = \"probe-sentinel\"\n",
            0o600,
        )?;
        Ok(Fixtures {
            probe,
            output,
            sentinel,
            marker,
            value,
        })
    }
}

/// Writes a new file at `path` (never through a link, never over one
/// there), mode `mode`.
fn new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), LocalError> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| LocalError::Fixtures)?;
    f.write_all(bytes).map_err(|_| LocalError::Fixtures)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|_| LocalError::Fixtures)
}

/// The probe-only daemon: see the module documentation.
pub struct ProbeDaemon {
    child: Option<Child>,
    /// The master side of its session's terminal: its lifeline.
    terminal: Option<std::os::fd::OwnedFd>,
    paths: RunPaths,
    env: Vec<(OsString, OsString)>,
    /// What it wrote to its standard error, at most [`MAX_LOG`] bytes.
    log: Arc<Mutex<Vec<u8>>>,
    passphrase: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for ProbeDaemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeDaemon")
            .field("pid", &self.child.as_ref().map(Child::id))
            .field("socket", &self.paths.socket)
            .finish_non_exhaustive()
    }
}

impl ProbeDaemon {
    /// Starts `envcloakd --foreground` (`envcloakd` an absolute path) with
    /// `env` after a cleared environment, in `home`'s directory, in a
    /// session of its own on a terminal of its own (its standard input, so
    /// the terminal is open in its session and the hang-up reaches it), and
    /// waits until it listens on `home`'s socket.
    ///
    /// # Errors
    /// [`LocalError::Daemon`] when it cannot be started or does not listen
    /// in time; it is stopped then.
    pub fn start(
        envcloakd: &Path,
        home: &LocalHome,
        env: &[(OsString, OsString)],
    ) -> Result<ProbeDaemon, LocalError> {
        if !envcloakd.is_absolute() {
            return Err(LocalError::Daemon);
        }
        let paths = home.run_paths()?;
        let pty = envcloak_sys::pty::open_pty(None, None).map_err(|_| LocalError::Daemon)?;
        let stdin = pty.slave.try_clone().map_err(|_| LocalError::Daemon)?;
        let mut cmd = Command::new(envcloakd);
        cmd.arg("--foreground")
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k, v)))
            .current_dir(home.root())
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        envcloak_sys::new_session_on_spawn(&mut cmd, Some(pty.slave.as_fd()))
            .map_err(|_| LocalError::Daemon)?;
        let mut child = crate::detect::spawn_unreaped(&mut cmd).map_err(|_| LocalError::Daemon)?;
        drop(cmd);
        drop(pty.slave);
        let log = Arc::new(Mutex::new(Vec::new()));
        if let Some(mut err) = child.stderr.take() {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = err.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let mut l = log.lock().unwrap_or_else(PoisonError::into_inner);
                    let room = MAX_LOG.saturating_sub(l.len());
                    l.extend_from_slice(&buf[..n.min(room)]);
                }
            });
        }
        let mut d = ProbeDaemon {
            child: Some(child),
            terminal: Some(pty.master),
            paths,
            env: env.to_vec(),
            log,
            passphrase: None,
        };
        let end = Instant::now() + DAEMON_START;
        loop {
            if d.connect().is_ok() {
                return Ok(d);
            }
            // A state not known is no daemon to wait for: `stop` kills it.
            let gone = d
                .child
                .as_ref()
                .is_none_or(|c| !matches!(envcloak_sys::has_exited(pid_of(c)), Ok(false)));
            if gone || Instant::now() > end {
                d.stop();
                return Err(LocalError::Daemon);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// A verified connection to it.
    ///
    /// # Errors
    /// As [`Client::connect`].
    pub fn connect(&self) -> Result<Client, ClientError> {
        Client::connect(&self.paths)
    }

    /// The environment it runs in (the probe home's, with `PATH`).
    pub fn env(&self) -> &[(OsString, OsString)] {
        &self.env
    }

    /// Its socket.
    pub fn socket(&self) -> &Path {
        &self.paths.socket
    }

    /// The probe passphrase, once [`ProbeDaemon::create_vault`] made it.
    pub fn passphrase(&self) -> Option<&Zeroizing<String>> {
        self.passphrase.as_ref()
    }

    /// Creates its throwaway vault: a generated passphrase, kept here; a
    /// generated Recovery Kit, dropped.
    ///
    /// # Errors
    /// [`LocalError::Vault`].
    pub fn create_vault(&mut self) -> Result<(), LocalError> {
        let pass = suggest_passphrase();
        let kit = RecoveryKit::generate().to_display();
        let mut client = self.connect().map_err(|_| LocalError::Vault)?;
        let created = client.vault_create(
            SecretBytes::copy_from(pass.as_bytes()),
            SecretBytes::copy_from(kit.as_bytes()),
            Some(KDF_MEMORY_KIB),
        );
        drop(kit);
        match created {
            Ok(v) if !v.locked => {
                self.passphrase = Some(pass);
                Ok(())
            }
            _ => Err(LocalError::Vault),
        }
    }

    /// Adds the probe item, holding `value`.
    fn add_item(&mut self, value: &str) -> Result<(), LocalError> {
        let mut client = self.connect().map_err(|_| LocalError::Fixtures)?;
        client
            .items_add(&AddParams {
                slug: Some(PROBE_SLUG.to_owned()),
                provider: None,
                field: None,
                account: None,
                env_hint: Some(PROBE_ENV.to_owned()),
                allow_short: false,
                value: WireSecret::new(SecretBytes::copy_from(value.as_bytes())),
                claims: Vec::new(),
            })
            .map(drop)
            .map_err(|_| LocalError::Fixtures)
    }

    /// Whether this process may give a proof, as the probe daemon judges
    /// it: it asks for the probe item's target, which the daemon serves
    /// only to such a caller (SPEC §10b) and refuses, audited, to an agent's
    /// process or one without a controlling terminal.
    pub fn may_approve(&self, claims: &[String]) -> bool {
        let Ok(mut client) = self.connect() else {
            return false;
        };
        match client.items_target(PROBE_SLUG, None, claims) {
            Ok(_) => true,
            Err(ClientError::Rpc(e)) if e.kind == ErrorKind::ProofRefused => false,
            Err(_) => false,
        }
    }

    /// The log it wrote so far (value-free by design: the daemon logs
    /// tokens and counts).
    pub fn log(&self) -> String {
        String::from_utf8_lossy(&self.log.lock().unwrap_or_else(PoisonError::into_inner))
            .into_owned()
    }

    /// Locks it, then asks it to stop (SIGTERM, to this process's own
    /// unreaped child), waits for it, and reaps it; one that does not stop
    /// in time is killed while still unreaped. Its terminal goes last.
    pub fn stop(&mut self) {
        if let Some(child) = self.child.take() {
            if let Ok(mut c) = self.connect() {
                let _ = c.lock();
            }
            let pid = pid_of(&child);
            // Signalled only while it is still this process's own unreaped
            // child (`has_exited` answers only for one; it was started by
            // `spawn_unreaped`): a pid not known to be its own may be
            // another process's by now, and gets nothing.
            if matches!(envcloak_sys::has_exited(pid), Ok(false)) {
                let _ = envcloak_sys::signal_process(pid, libc::SIGTERM);
            }
            let end = Instant::now() + DAEMON_STOP;
            while matches!(envcloak_sys::has_exited(pid), Ok(false)) && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(25));
            }
            let mut child = child;
            // Still running and still its own: killed while unreaped, so the
            // wait below never waits on a daemon that does not stop (Codex
            // cycle488 F144's class). A state not known is no child of this
            // process's to signal; the wait then returns at once.
            if matches!(envcloak_sys::has_exited(pid), Ok(false)) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        self.terminal = None;
        self.passphrase = None;
    }
}

impl Drop for ProbeDaemon {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A child's pid as the signal and wait calls take it.
fn pid_of(c: &Child) -> i32 {
    i32::try_from(c.id()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qualified_run() -> LocalRun {
        let host = ProbeHost {
            host: Host::ClaudeCode,
            exe: PathBuf::from("/nonexistent/claude"),
            version: "2.1.280".to_owned(),
        };
        let mut report = not_qualified(&host);
        for s in &mut report.surfaces {
            s.outcome = Outcome::Passed;
        }
        report.exe_sha256 = "e".repeat(64);
        report.config_digest = "p".repeat(64);
        report.config_shape = "s".repeat(64);
        LocalRun {
            report,
            qualification: Qualification::Qualified,
            approvals: 2,
            needs_terminal: false,
            home_removed: true,
        }
    }

    /// A result is kept under the person's binary and configuration only
    /// when every condition holds; each one broken alone is refused with
    /// its reason. Mutation checked: each condition taken out in turn
    /// (the binary's comparison, the before/after comparison, the hook
    /// programs' comparison, the shape's comparison): its case below then
    /// keeps the record and fails.
    #[test]
    fn a_result_is_kept_only_for_what_it_measured() {
        let run = qualified_run();
        let ours = crate::coverage::ProgramSeen {
            path: "/x/envcloak".to_owned(),
            sha256: Some("c".repeat(64)),
        };
        let theirs = crate::coverage::ProgramSeen {
            path: "/y/envcloak".to_owned(),
            sha256: Some("d".repeat(64)),
        };
        let gone = crate::coverage::ProgramSeen {
            path: "/z/envcloak".to_owned(),
            sha256: None,
        };
        let exe = "e".repeat(64);
        let fp = "f".repeat(64);
        let me = "c".repeat(64);
        let shape = "s".repeat(64);
        let other_shape = "t".repeat(64);
        let programs = [ours.clone(), gone.clone()];
        let good = PersonIdentity {
            exe_sha256: &exe,
            before: Some(&fp),
            after: Some(&fp),
            programs: &programs,
            envcloak_sha256: &me,
            shape: Some(&shape),
        };
        let r = keep_record(&run, &good).unwrap();
        assert_eq!(r.exe_sha256, exe);
        assert_eq!(r.config_digest, fp, "kept under the person's fingerprint");
        assert!(r.is_for("claude-code", &exe, "2.1.280", &fp));

        let other_fp = "g".repeat(64);
        let other_exe = "h".repeat(64);
        let both = [ours, theirs];
        for (case, person, want) in [
            (
                "binary not read",
                PersonIdentity {
                    exe_sha256: "",
                    ..good
                },
                NotKept::BinaryNotRead,
            ),
            (
                "no fingerprint",
                PersonIdentity {
                    before: None,
                    ..good
                },
                NotKept::ConfigurationNotRead,
            ),
            (
                "no fingerprint after",
                PersonIdentity {
                    after: None,
                    ..good
                },
                NotKept::ConfigurationNotRead,
            ),
            (
                "changed",
                PersonIdentity {
                    after: Some(&other_fp),
                    ..good
                },
                NotKept::ChangedWhileProbing,
            ),
            (
                "another binary",
                PersonIdentity {
                    exe_sha256: &other_exe,
                    ..good
                },
                NotKept::ChangedWhileProbing,
            ),
            (
                "another envcloak",
                PersonIdentity {
                    programs: &both,
                    ..good
                },
                NotKept::AnotherEnvcloak,
            ),
            (
                "another configuration shape",
                PersonIdentity {
                    shape: Some(&other_shape),
                    ..good
                },
                NotKept::ConfigurationDiffers,
            ),
            (
                "no shape",
                PersonIdentity {
                    shape: None,
                    ..good
                },
                NotKept::ConfigurationNotRead,
            ),
        ] {
            assert_eq!(keep_record(&run, &person), Err(want), "{case}");
        }
        let mut unidentified = qualified_run();
        unidentified.report.config_digest.clear();
        assert_eq!(
            keep_record(&unidentified, &good),
            Err(NotKept::ProbeNotIdentified)
        );
        let mut no_shape = qualified_run();
        no_shape.report.config_shape.clear();
        assert_eq!(
            keep_record(&no_shape, &good),
            Err(NotKept::ProbeNotIdentified)
        );

        // Not qualified: kept as such, under the person's identity, with
        // nothing measured to compare.
        let host = ProbeHost {
            host: Host::ClaudeCode,
            exe: PathBuf::from("/nonexistent/claude"),
            version: "2.1.999".to_owned(),
        };
        let nq = LocalRun {
            report: not_qualified(&host),
            qualification: qualify(Host::ClaudeCode, "2.1.999"),
            approvals: 0,
            needs_terminal: false,
            home_removed: true,
        };
        let r = keep_record(
            &nq,
            &PersonIdentity {
                programs: &both,
                ..good
            },
        )
        .unwrap();
        assert!(
            r.surfaces
                .iter()
                .all(|s| s.outcome == Outcome::NotQualified)
        );
        assert_eq!(r.server.outcome, Outcome::NotQualified);
    }

    /// The probe daemon is given the person's agent catalog extensions,
    /// only those their own daemon reads, byte for byte, so it knows their
    /// agents as their daemon does (the verifier's review of M2-28).
    /// Mutation checked: `probe_host` without its `copy_agent_extensions`
    /// call leaves the probe daemon the builtin catalog; this test then
    /// fails on `copy_agent_extensions` taken out of its body (the probe
    /// catalog lacks `pairbot`), and `probe_local.rs`'s
    /// `an_agent_only_an_extension_names_gets_probe_needs_terminal` fails
    /// on the call taken out.
    #[test]
    fn the_probe_daemon_gets_the_extensions_the_persons_daemon_reads() {
        use std::os::unix::fs::PermissionsExt as _;
        let person = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let probe = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let probe_data = probe.path().join("data");
        // Nothing to give: nothing made.
        copy_agent_extensions(person.path(), &probe_data).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(!probe_data.exists());

        let dir = person.path().join("agents.d");
        std::fs::create_dir(&dir).unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("{e}"));
        let write = |name: &str, body: &str, mode: u32| {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap_or_else(|e| panic!("{e}"));
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode))
                .unwrap_or_else(|e| panic!("{e}"));
        };
        let good = "[[agent]]\nid = \"pairbot\"\nname = \"Pairbot\"\nnames = [\"pairbot\"]\n";
        write("pairbot.toml", good, 0o600);
        // Skipped by the person's daemon: group-writable, hidden, a link.
        write(
            "shared.toml",
            "[[agent]]\nid = \"shared\"\nname = \"S\"\nnames = [\"shared\"]\n",
            0o664,
        );
        write(
            ".hidden.toml",
            "[[agent]]\nid = \"hidden\"\nname = \"H\"\nnames = [\"hidden\"]\n",
            0o600,
        );
        std::os::unix::fs::symlink(dir.join("pairbot.toml"), dir.join("link.toml"))
            .unwrap_or_else(|e| panic!("{e}"));

        copy_agent_extensions(person.path(), &probe_data).unwrap_or_else(|e| panic!("{e:?}"));
        let copied = probe_data.join("agents.d");
        let mut names: Vec<String> = std::fs::read_dir(&copied)
            .unwrap_or_else(|e| panic!("{e}"))
            .map(|e| {
                e.unwrap_or_else(|e| panic!("{e}"))
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(names, ["pairbot.toml"]);
        assert_eq!(
            std::fs::read_to_string(copied.join("pairbot.toml")).unwrap_or_default(),
            good
        );
        let mode = |p: &Path| {
            std::fs::metadata(p)
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(0)
        };
        assert_eq!(mode(&copied), 0o700);
        assert_eq!(mode(&copied.join("pairbot.toml")), 0o600);
        let probe_cat = envcloak_policy::AgentCatalog::load(&probe_data);
        let person_cat = envcloak_policy::AgentCatalog::load(person.path());
        let ids =
            |c: &envcloak_policy::AgentCatalog| c.ids().map(str::to_owned).collect::<Vec<String>>();
        assert!(ids(&probe_cat).iter().any(|i| i == "pairbot"));
        assert_eq!(ids(&probe_cat), ids(&person_cat));
        // The person's files are as they were.
        assert_eq!(mode(&dir.join("shared.toml")), 0o664);
    }

    /// What a probe runs is found beside `envcloak`, or `envcloakd` in the
    /// macOS app's helper; each of the three missing, or not executable, is
    /// refused (never a probe with a surface left out). Mutation checked:
    /// the MCP server made optional again (`locate_programs` without its
    /// `mcp` check): the case without it is found and this fails.
    #[test]
    fn the_probe_programs_are_found_where_they_ship() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let put = |p: &Path, mode: u32| {
            if let Some(d) = p.parent() {
                std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
            }
            std::fs::write(p, "#!/bin/sh\n").unwrap_or_else(|e| panic!("{e}"));
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
                .unwrap_or_else(|e| panic!("{e}"));
        };
        // A build tree: all beside it.
        let bin = root.path().join("bin");
        let me = bin.join("envcloak");
        for n in ["envcloak", "envcloakd", MODEL_PROGRAM, MCP_PROGRAM] {
            put(&bin.join(n), 0o755);
        }
        assert_eq!(
            locate_programs(&me),
            Ok(ProbePrograms {
                envcloakd: bin.join("envcloakd"),
                model: bin.join(MODEL_PROGRAM),
                mcp: bin.join(MCP_PROGRAM),
            })
        );
        // Each one missing or not executable.
        for n in ["envcloakd", MODEL_PROGRAM, MCP_PROGRAM] {
            put(&bin.join(n), 0o644);
            assert!(locate_programs(&me).is_err(), "{n} not executable");
            std::fs::remove_file(bin.join(n)).unwrap_or_else(|e| panic!("{e}"));
            assert!(locate_programs(&me).is_err(), "{n} missing");
            put(&bin.join(n), 0o755);
        }
        // The macOS app: the daemon in its helper.
        let app = root.path().join("EnvCloak.app").join("Contents");
        let cli = app.join("MacOS").join("envcloak");
        let daemon = app
            .join("Helpers")
            .join("EnvCloakAgent.app")
            .join("Contents")
            .join("MacOS")
            .join("envcloakd");
        for p in [&cli, &daemon] {
            put(p, 0o755);
        }
        for n in [MODEL_PROGRAM, MCP_PROGRAM] {
            put(&app.join("MacOS").join(n), 0o755);
        }
        assert_eq!(
            locate_programs(&cli).map(|p| p.envcloakd),
            Ok(daemon.clone())
        );
        // The helper's daemon is looked for only in an app's layout.
        let other = root.path().join("x").join("Contents").join("bin");
        for n in ["envcloak", MODEL_PROGRAM, MCP_PROGRAM] {
            put(&other.join(n), 0o755);
        }
        assert!(locate_programs(&other.join("envcloak")).is_err());
    }

    /// Each system or managed file a host loads whatever its home is
    /// found, for its host only; none, nothing. Mutation checked: each
    /// candidate taken out of `inherited_configuration` in turn: its case
    /// below is then not found and this fails.
    #[test]
    fn a_hosts_system_and_managed_configuration_is_found() {
        let root = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let home = root.path().join("home");
        let system = root.path().join("etc-codex");
        let prefs = root.path().join("managed-preferences");
        let claude = root.path().join("claude-managed");
        for d in [&home, &system, &prefs, &claude] {
            std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
        }
        let home_var = home.clone();
        let l = crate::locations::Locations::new(&|k| {
            (k == "HOME").then(|| home_var.as_os_str().to_owned())
        })
        .unwrap_or_else(|_| panic!("no home"))
        .with_system_dirs(system.clone(), prefs.clone());
        for host in [Host::ClaudeCode, Host::Codex] {
            assert!(
                inherited_configuration(host, &l, &claude).is_empty(),
                "{host:?}"
            );
        }
        let user = prefs.join("someone");
        std::fs::create_dir(&user).unwrap_or_else(|e| panic!("{e}"));
        let cases: [(Host, PathBuf); 10] = [
            (Host::ClaudeCode, claude.join("managed-settings.json")),
            (Host::ClaudeCode, claude.join("managed-settings.d")),
            (Host::ClaudeCode, claude.join("managed-mcp.json")),
            (
                Host::ClaudeCode,
                prefs.join("com.anthropic.claudecode.plist"),
            ),
            (
                Host::ClaudeCode,
                user.join("com.anthropic.claudecode.plist"),
            ),
            (Host::Codex, system.join("config.toml")),
            (Host::Codex, system.join("hooks.json")),
            (Host::Codex, system.join("managed_config.toml")),
            (Host::Codex, system.join("requirements.toml")),
            (Host::Codex, user.join("com.openai.codex.plist")),
        ];
        for (host, path) in cases {
            std::fs::write(&path, "").unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(
                inherited_configuration(host, &l, &claude),
                std::slice::from_ref(&path),
                "{host:?}"
            );
            let other = match host {
                Host::ClaudeCode => Host::Codex,
                Host::Codex => Host::ClaudeCode,
            };
            assert!(
                inherited_configuration(other, &l, &claude).is_empty(),
                "{path:?}"
            );
            std::fs::remove_file(&path).unwrap_or_else(|e| panic!("{e}"));
        }
    }

    #[test]
    fn only_codex_gets_the_trust_bypass() {
        assert_eq!(
            host_flags(Host::Codex).args,
            ["--dangerously-bypass-hook-trust"]
        );
        assert!(host_flags(Host::ClaudeCode).args.is_empty());
    }

    #[test]
    fn a_host_not_qualified_is_not_probed() {
        let host = ProbeHost {
            host: Host::ClaudeCode,
            exe: PathBuf::from("/nonexistent/claude"),
            version: "2.1.999".to_owned(),
        };
        let opts = LocalOptions {
            envcloak: PathBuf::from("/nonexistent/envcloak"),
            envcloakd: PathBuf::from("/nonexistent/envcloakd"),
            model_exe: PathBuf::from("/nonexistent/model"),
            mcp_fixture: None,
            path: OsString::new(),
            markers: Vec::new(),
            claims: Vec::new(),
            tmp: PathBuf::from("/nonexistent"),
            person_socket: None,
            person_data: PathBuf::from("/nonexistent"),
            run_limit: RUN_LIMIT,
        };
        let r = probe_host(&host, &opts).unwrap();
        assert!(!r.qualification.is_qualified());
        assert!(
            r.report
                .surfaces
                .iter()
                .all(|s| s.outcome == Outcome::NotQualified)
        );
        assert_eq!(r.report.surfaces.len(), Surface::ALL.len());
        assert_eq!(r.report.server.outcome, Outcome::NotQualified);
        assert!(r.report.runs.is_empty());
    }
}
