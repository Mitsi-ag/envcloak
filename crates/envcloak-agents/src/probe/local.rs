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
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
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
}

/// The record the cache keeps for `run`, under the person's identity, or
/// why it is not kept (L-09: a result is current only for what it
/// measured). Kept under the person's host binary and configuration
/// fingerprint: the probe measured that binary, with EnvCloak installed as
/// this build installs it, run by this `envcloak`; what the person's own
/// files switch off is applied at display from those files (the
/// fingerprint's facts). So the record is kept only when the binary the
/// probe ran is the person's, neither it nor the configuration changed
/// meanwhile, and the person's hooks run the same `envcloak`. A host
/// version that is not qualified is kept as `not_qualified` under the same
/// identity, so `agents status` says why it has no probe result.
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
        if run.report.exe_sha256.is_empty() || run.report.config_digest.is_empty() {
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
    }
    let mut record = run.report.record();
    record.exe_sha256 = person.exe_sha256.to_owned();
    record.config_digest = before.to_owned();
    Ok(record)
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
        let mut child = cmd.spawn().map_err(|_| LocalError::Daemon)?;
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
            let gone = d
                .child
                .as_ref()
                .is_none_or(|c| envcloak_sys::has_exited(pid_of(c)).unwrap_or(true));
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
            let _ = envcloak_sys::signal_process(pid, libc::SIGTERM);
            let end = Instant::now() + DAEMON_STOP;
            while !envcloak_sys::has_exited(pid).unwrap_or(true) && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(25));
            }
            let mut child = child;
            if !envcloak_sys::has_exited(pid).unwrap_or(true) {
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
    /// programs' comparison): its case below then keeps the record and
    /// fails.
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
        let programs = [ours.clone(), gone.clone()];
        let good = PersonIdentity {
            exe_sha256: &exe,
            before: Some(&fp),
            after: Some(&fp),
            programs: &programs,
            envcloak_sha256: &me,
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
        ] {
            assert_eq!(keep_record(&run, &person), Err(want), "{case}");
        }
        let mut unidentified = qualified_run();
        unidentified.report.config_digest.clear();
        assert_eq!(
            keep_record(&unidentified, &good),
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
