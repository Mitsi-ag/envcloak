//! The probe runner: each probe's runs of the host against the scripted
//! model, and what they establish (see [`super`]).
//!
//! A run starts `envcloak-probe-model` with the probe's script (a
//! [`ModelStub`], its own child), then the host with a cleared
//! environment (the probe home's, the model's settings, and every proxy
//! variable at the model, which refuses and records anything sent
//! elsewhere), leading a process group of its own, in the probe's
//! directory. The host's exit is seen without reaping it; then what is
//! left of its group (its MCP servers, its commands) is killed while the
//! leader is still unreaped, so the group's number cannot be anyone
//! else's (D-34), and only then is it reaped. A run that outlives the
//! probe home's limit is ended the same way and fails its probe. The
//! host's output is read and dropped: what counts is what the model
//! recorded and what the host stored.

use std::ffi::OsString;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::controls::{
    self, Watch, contains, denial, forms, halves, key_shaped, last_tool_output, marker, picked,
    reached, seen, session_uuid, unmarked, uuid_shaped,
};
use super::model::{self, ModelStub, Recorded};
use super::{
    Check, HostFlags, ProbeHome, ProbeHost, ProbeReport, RunSummary, ServerProbe, SurfaceProbe,
    claude, codex,
};
use crate::coverage::{self, Case, ConfigSet, Outcome, Reason, Sentinel, Surface};
use crate::hook::{Host, Reason as Denied};
use crate::hosts::shell_quote;
use crate::locations::Locations;

/// The proxy variables pointed at the model.
const PROXIES: [&str; 4] = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
/// How long the model may outlive the host's limit (its last report).
const MODEL_GRACE: Duration = Duration::from_secs(30);
/// The environment variable a shell probe looks for in the host's output.
const ENV_NAME: &str = "ECPROBE_ENV";
/// What Claude Code prints when EnvCloak's prompt hook blocks a prompt
/// (measured on the pinned 2.1.280: `UserPromptSubmit operation blocked by
/// hook:` and the hook's reason, whose marker this is).
pub const CLAUDE_BLOCKED: &str = "[envcloak:key_in_prompt]";
/// What Codex prints when a prompt hook blocks a prompt (measured on the
/// pinned 0.159.2, on its standard error; it names no hook and no
/// reason).
pub const CODEX_BLOCKED: &str = "hook: UserPromptSubmit Blocked";

/// Every surface and EnvCloak's server, probed: see [`super`].
pub fn run(host: &ProbeHost, home: &ProbeHome<'_>, flags: &HostFlags) -> ProbeReport {
    run_surfaces(host, home, flags, &Surface::ALL, true)
}

/// The probes of `surfaces` (and, with `server`, the sentinel probe of
/// EnvCloak's server) only.
pub fn run_surfaces(
    host: &ProbeHost,
    home: &ProbeHome<'_>,
    flags: &HostFlags,
    surfaces: &[Surface],
    server: bool,
) -> ProbeReport {
    let mut report = ProbeReport {
        host: host.host,
        version: host.version.clone(),
        surfaces: Vec::new(),
        server: ServerProbe {
            outcome: Outcome::Skipped,
            sentinel: Sentinel::NotRun,
            control_ran: false,
            allowed_write: false,
            control_denied: false,
            checks: Vec::new(),
        },
        runs: Vec::new(),
        flags: flags.args.clone(),
        exe_sha256: String::new(),
        config_digest: String::new(),
        config_shape: String::new(),
    };
    let want = |s: Surface| surfaces.contains(&s);
    if !model::qualified(host.host.id(), &host.version) {
        for s in Surface::ALL.into_iter().filter(|s| want(*s)) {
            report.surfaces.push(skipped(s, Outcome::NotQualified, &[]));
        }
        if server {
            report.server.outcome = Outcome::NotQualified;
        }
        return report;
    }
    let mut p = Prober {
        host,
        home,
        flags,
        runs: Vec::new(),
        config: None,
    };
    // What the result is for: the host binary run and the probe context
    // of the directory the hosts run in, each read before and after (Codex
    // review of M2-09: a result was kept under an identity the caller
    // chose, not the one probed). One that changed while probing, or
    // cannot be read, is no identity: the record is then current for
    // nothing (`ProbeRecord::is_for`).
    let exe = || {
        std::fs::canonicalize(&host.exe)
            .ok()
            .and_then(|e| coverage::file_sha256(&e))
    };
    let exe_before = exe();
    p.config = p.read_config();
    let digest_before = p
        .config
        .as_ref()
        .and_then(|c| c.fingerprint(&home.envcloak));
    let shape_before = p
        .config
        .as_ref()
        .and_then(|c| c.shape(&home.home, &home.envcloak));
    let fixtures = Fixtures::write(&home.project, &home.root);
    let Ok(fx) = fixtures else {
        // No control could be set up: every probe fails through it.
        for s in Surface::ALL.into_iter().filter(|s| want(*s)) {
            report
                .surfaces
                .push(failed(s, "the probe's fixture files could not be written"));
        }
        if server {
            report.server.outcome = Outcome::Failed;
        }
        return report;
    };
    if want(Surface::PromptToModel) || want(Surface::Transcript) {
        let (prompt, transcript) = p.prompt_and_transcript();
        if want(Surface::PromptToModel) {
            report.surfaces.push(prompt);
        }
        if want(Surface::Transcript) {
            report.surfaces.push(transcript);
        }
    }
    if want(Surface::FileRead) {
        report.surfaces.push(p.file_read(&fx));
    }
    if want(Surface::Shell) {
        report.surfaces.push(p.shell(&fx));
    }
    if want(Surface::Mcp) {
        report.surfaces.push(p.mcp(&fx));
    }
    if want(Surface::Output) {
        report.surfaces.push(p.output());
    }
    if server {
        report.server = p.sentinel();
    }
    let after = p.read_config();
    let digest_after = after.as_ref().and_then(|c| c.fingerprint(&home.envcloak));
    let shape_after = after
        .as_ref()
        .and_then(|c| c.shape(&home.home, &home.envcloak));
    report.config_digest = match (digest_before, digest_after) {
        (Some(a), Some(b)) if a == b => a,
        _ => String::new(),
    };
    report.config_shape = match (shape_before, shape_after) {
        (Some(a), Some(b)) if a == b => a,
        _ => String::new(),
    };
    report.exe_sha256 = match (exe_before, exe()) {
        (Some(a), Some(b)) if a == b => a,
        _ => String::new(),
    };
    report.runs = p.runs;
    report.surfaces.sort_by_key(|s| s.surface);
    report
}

fn skipped(surface: Surface, outcome: Outcome, why: &[Reason]) -> SurfaceProbe {
    SurfaceProbe {
        surface,
        outcome,
        checks: Vec::new(),
        persisted: false,
        why: why.to_vec(),
        skipped: Vec::new(),
    }
}

fn failed(surface: Surface, why: &'static str) -> SurfaceProbe {
    SurfaceProbe {
        surface,
        outcome: Outcome::Failed,
        checks: vec![Check {
            name: "set up",
            control: true,
            passed: false,
            why,
        }],
        persisted: false,
        why: Vec::new(),
        skipped: Vec::new(),
    }
}

fn check(name: &'static str, control: bool, passed: bool, why: &'static str) -> Check {
    Check {
        name,
        control,
        passed,
        why: if passed { "" } else { why },
    }
}

/// A surface whose outcome is passed only when every check passed.
fn surface(surface: Surface, checks: Vec<Check>) -> SurfaceProbe {
    let outcome = if checks.iter().all(|c| c.passed) {
        Outcome::Passed
    } else {
        Outcome::Failed
    };
    SurfaceProbe {
        surface,
        outcome,
        checks,
        persisted: false,
        why: Vec::new(),
        skipped: Vec::new(),
    }
}

/// The files a probe writes: in its project, `README.md` holding a marker
/// (the read control) and `.env` holding another (what must never reach
/// the model); the same `.env` in a folder of the probe's own beside the
/// project ([`ELSEWHERE`]), outside the session's working directory; and a
/// third marker for the host's environment (the shell probe's).
struct Fixtures {
    readme: String,
    env_file: Zeroizing<String>,
    env_var: Zeroizing<String>,
    /// The folder outside the project holding the other `.env`, resolved.
    elsewhere: PathBuf,
}

/// The folder of the probe's own, in its root, that holds a `.env`
/// outside the session's working directory.
const ELSEWHERE: &str = "ecprobe-elsewhere";

impl Fixtures {
    fn write(project: &Path, root: &Path) -> std::io::Result<Fixtures> {
        let elsewhere = root.join(ELSEWHERE);
        match std::fs::DirBuilder::new().mode(0o700).create(&elsewhere) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if !std::fs::symlink_metadata(&elsewhere)?.is_dir() {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
        let fx = Fixtures {
            readme: marker("readme")?,
            env_file: Zeroizing::new(marker("envfile")?),
            env_var: Zeroizing::new(marker("envvar")?),
            elsewhere: std::fs::canonicalize(&elsewhere)?,
        };
        write_file(
            &project.join("README.md"),
            format!("# Probe\n\n{}\n", fx.readme).as_bytes(),
        )?;
        let env = Zeroizing::new(format!("ECPROBE_FIXTURE={}\n", fx.env_file.as_str()));
        write_file(&project.join(".env"), env.as_bytes())?;
        write_file(&fx.elsewhere.join(".env"), env.as_bytes())?;
        Ok(fx)
    }
}

/// Writes `bytes` to `path`, replacing what was there, never through a
/// link at its last component.
fn write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.is_file() => return Err(std::io::ErrorKind::AlreadyExists.into()),
        Ok(_) => std::fs::remove_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)
}

/// How a run joins a session.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Session {
    /// A session of its own.
    New,
    /// Claude Code: a new session under this id (`--session-id`).
    Named(String),
    /// The session with this id, resumed (Claude Code `--resume`, Codex
    /// `exec resume`).
    Resume(String),
}

/// One run of the host.
struct Spec {
    name: &'static str,
    script: Value,
    prompt: Zeroizing<String>,
    /// The probe's own flags (Claude Code) or `-c` settings (Codex).
    probe: Vec<String>,
    /// Codex's sandbox.
    sandbox: &'static str,
    env: Vec<(OsString, OsString)>,
    cwd: PathBuf,
    /// Whether the run needs an approval while it runs.
    approve: bool,
    session: Session,
    /// Fixed texts looked for in what the host prints, which is read and
    /// dropped as it comes ([`Watch`]): never kept, never shown.
    watch: Vec<&'static str>,
}

/// What one run left: the requests the model recorded during it (wiped
/// on drop), how the host ended, and which watched texts it printed.
#[derive(Default)]
struct HostRun {
    requests: Vec<Recorded>,
    clean: bool,
    exit: Option<i32>,
    timed_out: bool,
    approved: Option<bool>,
    printed: Vec<bool>,
}

impl HostRun {
    /// The run is evidence at all: the host exited 0 in time and the model
    /// served everything its session was sent (a refused token, an unknown
    /// route, a malformed body, a cap reached all say the run is not one
    /// to read).
    fn usable(&self) -> bool {
        self.exit == Some(0) && !self.timed_out && self.clean
    }

    /// What the tool call of step `n - 1` returned, in the request that
    /// step `n` answered.
    fn after(&self, n: usize) -> Zeroizing<String> {
        picked(&self.requests, n).map_or_else(|| Zeroizing::new(String::new()), last_tool_output)
    }
}

/// One scripted model serving every run of a session: a probe and its
/// controls reach the same receiver (Codex review of M2-09: the prompt
/// probe and its control each had a model of their own, so a control's
/// delivery said nothing of the probe's run).
struct Receiver {
    stub: ModelStub,
    base: String,
    token: Zeroizing<String>,
    /// The last request number given to a run.
    seen: u64,
    /// The runs it served, by their place in [`Prober::runs`].
    served: Vec<usize>,
}

struct Prober<'p, 'a> {
    host: &'p ProbeHost,
    home: &'p ProbeHome<'a>,
    flags: &'p HostFlags,
    runs: Vec<RunSummary>,
    /// The host's configuration in the probe's directory, as read before
    /// the probes: what tells a refusal or a block as EnvCloak's.
    config: Option<ConfigSet>,
}

impl Prober<'_, '_> {
    fn claude(&self) -> bool {
        self.host.host == Host::ClaudeCode
    }

    fn spec(&self, name: &'static str, script: Value, prompt: String) -> Spec {
        Spec {
            name,
            script,
            prompt: Zeroizing::new(prompt),
            probe: if self.claude() {
                claude::permissions(&[])
            } else {
                Vec::new()
            },
            sandbox: "read-only",
            env: Vec::new(),
            cwd: self.home.project.clone(),
            approve: false,
            session: Session::New,
            watch: Vec::new(),
        }
    }

    /// The host's file locations in the probe home's environment.
    fn locations(&self) -> Option<Locations> {
        let env = |k: &str| {
            self.home
                .env
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
        };
        Locations::new(&env).ok()
    }

    /// The host's configuration for a session in the probe's directory,
    /// read as `agents status` reads it.
    fn read_config(&self) -> Option<ConfigSet> {
        let env = |k: &str| {
            self.home
                .env
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
        };
        let l = self.locations()?;
        Some(ConfigSet::read(
            self.host.host,
            &l,
            &coverage::claude_managed_dir(),
            &self.home.project,
            &env,
        ))
    }

    /// A model for a session of `runs` runs of `script`.
    fn receiver(&self, script: &Value, runs: u32) -> Option<Receiver> {
        let bytes = serde_json::to_vec(script).ok().map(Zeroizing::new)?;
        let limit = self.home.run_limit.saturating_mul(runs.max(1)) + MODEL_GRACE;
        let stub = ModelStub::start(&self.home.model_exe, &bytes, limit).ok()?;
        let base = stub.base_url();
        let token = Zeroizing::new(stub.api_key().as_str().to_owned());
        Some(Receiver {
            stub,
            base,
            token,
            seen: 0,
            served: Vec::new(),
        })
    }

    /// Ends a session: whether the model served everything it was sent,
    /// to its end; each run's summary says so too.
    fn finish(&mut self, rx: Receiver) -> bool {
        let clean = rx.stub.finish().is_ok_and(|r| r.outcome.clean());
        for i in rx.served {
            if let Some(r) = self.runs.get_mut(i) {
                r.clean &= clean;
            }
        }
        clean
    }

    /// Runs the host once as `spec` says, against a model of its own.
    fn run(&mut self, spec: &Spec) -> HostRun {
        let Some(mut rx) = self.receiver(&spec.script, 1) else {
            self.runs
                .push(self.summary(spec, &HostRun::default(), Instant::now()));
            return HostRun::default();
        };
        let mut out = self.run_on(&mut rx, spec);
        out.clean &= self.finish(rx);
        out
    }

    fn summary(&self, spec: &Spec, out: &HostRun, start: Instant) -> RunSummary {
        let mut flags = spec.probe.clone();
        match (&spec.session, self.host.host) {
            (Session::Named(_), _) => flags.push("--session-id <the probe's>".to_owned()),
            (Session::Resume(_), Host::ClaudeCode) => {
                flags.push("--resume <the control's session>".to_owned());
            }
            (Session::Resume(_), Host::Codex) => {
                flags.push("resume <the control's session>".to_owned());
                flags.push(format!("-c sandbox_mode={}", codex::toml_str(spec.sandbox)));
            }
            (Session::New, Host::Codex) => {
                flags.extend(["--sandbox".to_owned(), spec.sandbox.to_owned()]);
            }
            (Session::New, Host::ClaudeCode) => {}
        }
        flags.extend(self.flags.args.iter().cloned());
        RunSummary {
            name: spec.name,
            flags,
            exit: out.exit,
            timed_out: out.timed_out,
            requests: out.requests.len(),
            clean: out.clean,
            elapsed: start.elapsed(),
            approved: out.approved,
        }
    }

    /// Runs the host once as `spec` says, against `rx`: the requests it
    /// made are those the model recorded since the session's last run.
    fn run_on(&mut self, rx: &mut Receiver, spec: &Spec) -> HostRun {
        let start = Instant::now();
        let mut out = self.run_inner(rx, spec, start);
        match rx.stub.requests() {
            Ok(report) => {
                out.clean = report.outcome.clean();
                let before = rx.seen;
                rx.seen = report
                    .requests
                    .iter()
                    .map(|r| r.seq)
                    .max()
                    .unwrap_or(before)
                    .max(before);
                out.requests = report
                    .requests
                    .into_iter()
                    .filter(|r| r.seq > before)
                    .collect();
            }
            Err(_) => out.clean = false,
        }
        self.runs.push(self.summary(spec, &out, start));
        rx.served.push(self.runs.len() - 1);
        out
    }

    fn run_inner(&self, rx: &Receiver, spec: &Spec, start: Instant) -> HostRun {
        let mut out = HostRun {
            printed: vec![false; spec.watch.len()],
            ..HostRun::default()
        };
        let base = &rx.base;
        let token = &rx.token;
        let mut cmd = Command::new(&self.host.exe);
        cmd.env_clear()
            .envs(self.home.env.iter().map(|(k, v)| (k, v)));
        for k in PROXIES {
            cmd.env(k, base);
        }
        for k in ["NO_PROXY", "no_proxy"] {
            cmd.env(k, "127.0.0.1,localhost");
        }
        let args = match self.host.host {
            Host::ClaudeCode => {
                cmd.envs(claude::model_env(base, token));
                let mut probe = spec.probe.clone();
                match &spec.session {
                    Session::New => {}
                    Session::Named(id) => probe.extend(["--session-id".to_owned(), id.clone()]),
                    Session::Resume(id) => probe.extend(["--resume".to_owned(), id.clone()]),
                }
                claude::args(&spec.prompt, &probe, &self.flags.args)
            }
            Host::Codex => {
                cmd.envs(codex::model_env(token));
                match &spec.session {
                    Session::Resume(id) => codex::resume_args(
                        base,
                        id,
                        &spec.prompt,
                        spec.sandbox,
                        &spec.probe,
                        &self.flags.args,
                    ),
                    _ => codex::args(
                        base,
                        &spec.prompt,
                        spec.sandbox,
                        &spec.probe,
                        &self.flags.args,
                    ),
                }
            }
        };
        cmd.args(&args)
            .envs(spec.env.iter().map(|(k, v)| (k, v)))
            .current_dir(&spec.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // A session of its own on a terminal of its own (M2-28): nothing it
        // or its commands do shares a session or a terminal with the
        // approver's, so its requests can be approved (T9-3), and its
        // process group is its pid's.
        let Ok(mut session) = HostSession::spawn(cmd) else {
            return out;
        };
        let child = &mut session.child;
        drop(args);
        let readers = [
            drain(child.stdout.take(), spec.watch.clone()),
            drain(child.stderr.take(), spec.watch.clone()),
        ];
        let deadline = start + self.home.run_limit;
        let stop = AtomicBool::new(false);
        let pid = i32::try_from(child.id()).unwrap_or(0);
        let approver = self.home.approver.filter(|_| spec.approve);
        let (timed_out, status, approved) = std::thread::scope(|s| {
            let approval = approver.map(|a| {
                let stop = &stop;
                s.spawn(move || a.approve(deadline, stop).is_ok())
            });
            let mut timed_out = false;
            loop {
                match envcloak_sys::has_exited(pid) {
                    Ok(true) | Err(_) => break,
                    Ok(false) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Ok(false) => {
                        timed_out = true;
                        break;
                    }
                }
            }
            // The host is this process's unreaped child: its group's number
            // is still its own (D-34). What is left there goes now.
            let _ = envcloak_sys::signal_group(pid, libc::SIGKILL);
            let status = child.wait().ok();
            stop.store(true, Ordering::SeqCst);
            let approved = approval.map(|h| h.join().unwrap_or(false));
            (timed_out, status, approved)
        });
        // The session's terminal goes with it: whatever of the session is
        // left gets its hang-up.
        session.hang_up();
        let left = (deadline + Duration::from_secs(5)).saturating_duration_since(Instant::now());
        for r in readers {
            if let Ok(found) = r.recv_timeout(left) {
                for (seen, f) in out.printed.iter_mut().zip(found) {
                    *seen |= f;
                }
            }
        }
        out.timed_out = timed_out;
        out.exit = if timed_out {
            None
        } else {
            status.and_then(|s| s.code())
        };
        out.approved = approved;
        out
    }

    /// The prompt guard and the transcript, from one session against one
    /// model (Codex review of M2-09: the control and the probe ran as two
    /// sessions, so a probe run that ended without sending anything read
    /// as a block, and the sweep took a control any session left):
    ///
    /// 1. the control: a benign prompt carrying a marker, in a session of
    ///    its own (Claude Code's under an id the probe gives it), must
    ///    reach the model;
    /// 2. that session is found by its control in the host's store: its
    ///    own file (Claude Code's `projects/<folder>/<id>.jsonl`, Codex's
    ///    one `sessions/**/rollout-*-<id>.jsonl` that holds the control);
    /// 3. the probe, the same session resumed with a prompt holding a
    ///    runtime-generated key-shaped token: the host must report the
    ///    block (Codex cycle177's hook invocation: Claude Code prints the
    ///    hook's reason, EnvCloak's marker in it; Codex prints that a
    ///    prompt hook blocked it, which counts only where no other prompt
    ///    hook is there), and the token must reach the model in no run;
    /// 4. the session resumed again with a second marker, which must reach
    ///    the model with the control's turn in the same request: the host
    ///    and the session went on after the block.
    ///
    /// The transcript is then swept: the control must be found in its
    /// session's file by the sweep, which must have read everything, and
    /// only then does the token's absence count.
    fn prompt_and_transcript(&mut self) -> (SurfaceProbe, SurfaceProbe) {
        let (Ok(ctl), Ok(again), Ok(token), Ok(id)) = (
            marker("prompt"),
            marker("again"),
            key_shaped(),
            session_uuid(),
        ) else {
            return (
                failed(Surface::PromptToModel, "no random bytes"),
                failed(Surface::Transcript, "no random bytes"),
            );
        };
        let script = json!({"steps": [{"say": "done"}]});
        let Some(mut rx) = self.receiver(&script, 3) else {
            return (
                failed(Surface::PromptToModel, "the scripted model could not start"),
                failed(Surface::Transcript, "the scripted model could not start"),
            );
        };
        let claude = self.claude();
        let mut a = self.spec(
            "prompt control",
            script.clone(),
            format!("Reply with one word. {ctl}"),
        );
        if claude {
            a.session = Session::Named(id.clone());
        }
        let mut ra = self.run_on(&mut rx, &a);
        let ctl_forms = forms(ctl.as_bytes());
        let found = self.session_store(&ctl_forms, claude.then_some(id.as_str()));
        let (mut rb, mut rc) = (HostRun::default(), HostRun::default());
        if let Some((_, sid)) = &found {
            let mut b = self.spec(
                "prompt probe",
                script.clone(),
                format!("Deploy it with {} now.", token.as_str()),
            );
            b.session = Session::Resume(sid.clone());
            b.watch = vec![if claude {
                CLAUDE_BLOCKED
            } else {
                CODEX_BLOCKED
            }];
            rb = self.run_on(&mut rx, &b);
            let mut c = self.spec(
                "prompt control after the block",
                script,
                format!("Reply with one word. {again}"),
            );
            c.session = Session::Resume(sid.clone());
            rc = self.run_on(&mut rx, &c);
        }
        let clean = self.finish(rx);
        for r in [&mut ra, &mut rb, &mut rc] {
            r.clean &= clean;
        }
        let control = ra.usable() && reached(&ra.requests, &ctl);
        let reported = rb.usable() && rb.printed.first().copied().unwrap_or(false);
        // Codex names no hook: its report counts only where EnvCloak's is
        // the only prompt hook (the class of the verifier's round-2
        // finding, a refusal taken as EnvCloak's without its provenance).
        let ours = claude
            || (self.config.as_ref().is_some_and(|c| !c.foreign_prompt_hook)
                && !flags_add_rules_or_hooks(self.host.host, &self.flags.args));
        let token_forms = forms(token.as_bytes());
        let kept_out = rb.usable()
            && !seen(&ra.requests, &token_forms)
            && !seen(&rb.requests, &token_forms)
            && !seen(&rc.requests, &token_forms);
        let went_on = rc.usable() && reached(&rc.requests, &again) && reached(&rc.requests, &ctl);
        drop((ra, rb, rc));
        let prompt = surface(
            Surface::PromptToModel,
            vec![
                check(
                    "a benign prompt reaches the model",
                    true,
                    control,
                    "the control did not reach the model",
                ),
                check(
                    "the control's session is found in the host's store",
                    true,
                    found.is_some(),
                    "no one session file of the host's store holds the control",
                ),
                check(
                    "the host reports EnvCloak's hook blocked the prompt",
                    false,
                    reported && ours,
                    if reported {
                        "a prompt hook blocked it, not known to be EnvCloak's"
                    } else {
                        "the host did not report a prompt hook blocking it"
                    },
                ),
                check(
                    "a prompt holding a key-shaped token never reaches it",
                    false,
                    kept_out,
                    "the token reached the model, or the run did not finish",
                ),
                check(
                    "the session goes on after the block, the control's turn in it",
                    true,
                    went_on,
                    "the session's next turn did not reach the model with the control's turn",
                ),
            ],
        );
        let blocked = prompt.outcome == Outcome::Passed;
        let (stores, known) = self.stores();
        let swept = controls::sweep(&stores, &[&ctl_forms, &token_forms]);
        let in_session = found
            .as_ref()
            .is_some_and(|(file, _)| swept.holders[0].iter().any(|h| h == file));
        let transcript = transcript(blocked, known, swept.complete, in_session, swept.found[1]);
        (prompt, transcript)
    }

    /// The store file of the session the control `ctl_forms` ran in, and
    /// the session's id: for Claude Code, the transcript named by the id
    /// the probe gave it (`claude_id`) that holds the control; for Codex,
    /// the one session file holding the control, its id from its name
    /// (`rollout-<time>-<id>.jsonl`). `None` unless exactly one is found.
    fn session_store(
        &self,
        ctl_forms: &[Zeroizing<Vec<u8>>],
        claude_id: Option<&str>,
    ) -> Option<(PathBuf, String)> {
        let l = self.locations()?;
        let root = if self.claude() {
            l.claude_dir().join("projects")
        } else {
            l.codex_home().join("sessions")
        };
        let swept = controls::sweep(&[(root, None)], &[ctl_forms]);
        let id_of = |p: &Path| -> Option<String> {
            let name = p.file_name()?.to_str()?;
            match claude_id {
                Some(id) => (name == format!("{id}.jsonl")).then(|| id.to_owned()),
                None if !self.claude() => {
                    let stem = name.strip_prefix("rollout-")?.strip_suffix(".jsonl")?;
                    let id = stem.get(stem.len().checked_sub(36)?..)?;
                    uuid_shaped(id).then(|| id.to_owned())
                }
                None => None,
            }
        };
        let mut hits = swept.holders[0]
            .iter()
            .filter_map(|p| Some((p.clone(), id_of(p)?)));
        let first = hits.next()?;
        hits.next().is_none().then_some(first)
    }

    /// The host's stores for a pasted or printed value (D-15), as the
    /// probe context names them (Codex's round-3 review: they were taken
    /// from the catalog and the user's `config.toml` alone, so a store
    /// another layer moved was never swept and the sweep still read
    /// whole): wherever the probe home's environment and every layer of
    /// the host's settings place them ([`coverage::Context::stores`]), and
    /// where a `-c` setting of the home's flags moves Codex's. And whether
    /// those are all the stores there are: not when the context could not
    /// be read, a layer that can move one cannot be read, or a setting
    /// moves one where this cannot tell.
    fn stores(&self) -> (Vec<(PathBuf, Option<String>)>, bool) {
        let Some(c) = self.config.as_ref() else {
            return (Vec::new(), false);
        };
        let mut roots = c.context.sweep_roots();
        let mut known = c.context.stores_known;
        if !self.claude() {
            for (key, value) in codex::settings(&self.flags.args) {
                let names = match key.as_str() {
                    "log_dir" => None,
                    "sqlite_home" => Some(".sqlite".to_owned()),
                    _ => continue,
                };
                match codex::setting_path(&value, &self.home.home) {
                    Some(dir) => roots.push((dir, names)),
                    None => known = false,
                }
            }
        }
        (roots, known)
    }

    /// Whether a refusal in the host's own words, of a call EnvCloak's host
    /// rule covers, can only be that rule's (the verifier's round-2
    /// finding: Claude Code's refusal names no rule, so any deny rule of
    /// the person's gave it): Claude Code's when its settings hold
    /// EnvCloak's `Read(**/.env*)` and no other deny rule for its file
    /// tools; Codex's refusal carries the justification of EnvCloak's own
    /// rule ([`controls::codex_rule_refused`]).
    fn rule_is_ours(&self) -> bool {
        !self.claude()
            || (self
                .config
                .as_ref()
                .is_some_and(|c| c.read_deny && !c.foreign_read_deny)
                && !flags_add_rules_or_hooks(self.host.host, &self.flags.args))
    }

    /// File read: a control read; the hook's case, a read of a `.env`
    /// that must be denied with EnvCloak's marker; the rule's case, the
    /// read EnvCloak's own host rule covers, which must be refused; and
    /// (Claude Code) the `@` mentions.
    ///
    /// The hook's case is a call EnvCloak's installed host rules leave to
    /// the hook, so the marker can only be the hook's and a hook taken out
    /// fails it; the call a rule covers is the rule's case, refused by the
    /// rule or the hook. One rule for both hosts (the verifier's finding:
    /// the two probes treated a refusal by EnvCloak's own rule two ways).
    /// Claude Code checks its deny rules before any hook, and
    /// `Read(**/.env*)` matches within the session's working directory
    /// (measured on 2.1.280: the project's `.env`, named by the resolved
    /// path the working directory is, is refused by the rule; a `.env`
    /// outside it reaches EnvCloak's hook), so its hook's case reads the
    /// `.env` in a folder beside the project ([`ELSEWHERE`]), and its
    /// rule's case the project's. Codex's `forbidden` rules match `cat
    /// .env` by its prefix: its hook's case is `cat -- .env`, its rule's
    /// case `cat .env`.
    fn file_read(&mut self, fx: &Fixtures) -> SurfaceProbe {
        let Ok(project) = std::fs::canonicalize(&self.home.project) else {
            return failed(
                Surface::FileRead,
                "the probe's project could not be resolved",
            );
        };
        let steps = if self.claude() {
            [
                claude::read_step(&project.join("README.md")),
                claude::read_step(&fx.elsewhere.join(".env")),
                claude::read_step(&project.join(".env")),
            ]
        } else {
            [
                json!({"shell": "cat README.md"}),
                json!({"shell": "cat -- .env"}),
                json!({"shell": "cat .env"}),
            ]
        };
        let [control, hook, rule] = steps;
        let mut spec = self.spec(
            "file read",
            json!({"steps": [control, hook, rule, {"say": "done"}]}),
            "Read the project's README and the .env files.".to_owned(),
        );
        if self.claude() {
            spec.probe = claude::permissions(&["Bash", "Read"]);
        }
        let r = self.run(&spec);
        let env_forms = forms(fx.env_file.as_bytes());
        let mut checks = denial_checks(&r, &fx.readme, Denied::EnvFile, &env_forms);
        checks.push(rule_check(&r, 3, self.host.host, self.rule_is_ours()));
        drop(r);
        let mut skipped = Vec::new();
        if self.claude() {
            let (more, not_run) = self.mentions(fx, &env_forms);
            checks.extend(more);
            skipped.extend(not_run);
        }
        let mut out = surface(Surface::FileRead, checks);
        out.skipped = skipped;
        out
    }

    /// Claude Code's `@` mentions: `@README.md` (whose content must
    /// arrive) and `@.env` (whose content must not), each prompt carrying a
    /// marker of its own that must arrive. Where the host does not expand
    /// `@` mentions under `-p`, the case is not run: it is returned apart
    /// ([`Case::AtMention`]), never as a check that passed.
    fn mentions(
        &mut self,
        fx: &Fixtures,
        env_forms: &[Zeroizing<Vec<u8>>],
    ) -> (Vec<Check>, Option<Case>) {
        let (Ok(m1), Ok(m2)) = (marker("mention"), marker("mention")) else {
            return (
                vec![check("mentions", true, false, "no random bytes")],
                None,
            );
        };
        let script = json!({"steps": [{"say": "done"}]});
        let spec = self.spec(
            "mention control",
            script.clone(),
            format!("Summarize @README.md for me. {m1}"),
        );
        let a = self.run(&spec);
        let arrived = a.usable() && reached(&a.requests, &m1);
        let expanded = arrived && reached(&a.requests, &fx.readme);
        drop(a);
        if !arrived {
            return (
                vec![check(
                    "an @README.md mention reaches the model",
                    true,
                    false,
                    "the control mention did not reach the model",
                )],
                None,
            );
        }
        if !expanded {
            // A host that does not expand `@` mentions under `-p` leaves
            // that case to M2-26's interactive variant: not run here, and
            // said so with the surface, never counted as passed.
            return (Vec::new(), Some(Case::AtMention));
        }
        let spec = self.spec(
            "mention probe",
            script,
            format!("Summarize @.env for me. {m2}"),
        );
        let b = self.run(&spec);
        let arrived = b.usable() && reached(&b.requests, &m2);
        let leaked = seen(&b.requests, env_forms);
        (
            vec![
                check(
                    "an @README.md mention's content reaches the model",
                    true,
                    true,
                    "",
                ),
                check(
                    "an @.env mention reaches the model as a prompt",
                    true,
                    arrived,
                    "the @.env prompt did not reach the model",
                ),
                check(
                    "the @.env file's content never does",
                    false,
                    !leaked,
                    "the @.env file's content reached the model",
                ),
            ],
            None,
        )
    }

    /// Shell: a printed marker must reach the model; printing the
    /// environment must be denied with EnvCloak's marker, and a variable
    /// of the host's environment never reach it. As for the file read
    /// ([`Self::file_read`]), the hook's case is a call EnvCloak's host
    /// rules leave to the hook (Codex's `forbidden` rules match `printenv`,
    /// so Codex's is `env`), and Codex's rule's case, `printenv`, must be
    /// refused; Claude Code has no host rule for the shell.
    fn shell(&mut self, fx: &Fixtures) -> SurfaceProbe {
        let Ok(ctl) = marker("shell") else {
            return failed(Surface::Shell, "no random bytes");
        };
        let (a, b) = halves(&ctl);
        let mut steps = vec![json!({"shell": format!("printf '%s%s\\n' '{a}' '{b}'")})];
        if self.claude() {
            steps.push(json!({"shell": "printenv"}));
        } else {
            steps.push(json!({"shell": "env"}));
            steps.push(json!({"shell": "printenv"}));
        }
        steps.push(json!({"say": "done"}));
        let mut spec = self.spec(
            "shell",
            json!({ "steps": steps }),
            "Print a marker, then the environment.".to_owned(),
        );
        if self.claude() {
            spec.probe = claude::permissions(&["Bash", "Read"]);
        }
        spec.env = vec![(ENV_NAME.into(), fx.env_var.as_str().into())];
        let r = self.run(&spec);
        let env_forms = forms(fx.env_var.as_bytes());
        let mut checks = denial_checks(&r, &ctl, Denied::EnvDump, &env_forms);
        if !self.claude() {
            checks.push(rule_check(&r, 3, self.host.host, self.rule_is_ours()));
        }
        surface(Surface::Shell, checks)
    }

    /// MCP: the fixture server's `echo` must answer; its `read_file` of
    /// `.env` must be denied with EnvCloak's marker.
    fn mcp(&mut self, fx: &Fixtures) -> SurfaceProbe {
        let Some(fixture) = self.home.mcp_fixture.clone() else {
            return skipped(Surface::Mcp, Outcome::Skipped, &[]);
        };
        let Ok(ctl) = marker("mcp") else {
            return failed(Surface::Mcp, "no random bytes");
        };
        let (a, b) = halves(&ctl);
        let echo = json!({"text": a, "more": b});
        let read = json!({"path": ".env"});
        let (s1, s2, server) = if self.claude() {
            (
                claude::mcp_step(claude::MCP_SERVER, "echo", echo),
                claude::mcp_step(claude::MCP_SERVER, "read_file", read),
                claude::MCP_SERVER,
            )
        } else {
            (
                codex::mcp_step(codex::MCP_SERVER, "echo", echo),
                codex::mcp_step(codex::MCP_SERVER, "read_file", read),
                codex::MCP_SERVER,
            )
        };
        let mut spec = self.spec(
            "mcp",
            json!({"steps": [s1, s2, {"say": "done"}]}),
            "Use the probe's MCP tools.".to_owned(),
        );
        if self.claude() {
            let config = self.home.root.join("ecprobe-mcp.json");
            let body = claude::mcp_config(&fixture).to_string();
            if write_file(&config, body.as_bytes()).is_err() {
                return failed(Surface::Mcp, "the MCP configuration could not be written");
            }
            let echo_tool = claude::mcp_tool(server, "echo");
            let read_tool = claude::mcp_tool(server, "read_file");
            spec.probe = claude::permissions(&[&echo_tool, &read_tool]);
            spec.probe.extend([
                "--mcp-config".to_owned(),
                config.to_string_lossy().into_owned(),
            ]);
        } else {
            spec.probe = codex::mcp_server(&fixture.to_string_lossy());
        }
        let r = self.run(&spec);
        let env_forms = forms(fx.env_file.as_bytes());
        surface(
            Surface::Mcp,
            denial_checks(&r, &ctl, Denied::EnvFile, &env_forms),
        )
    }

    /// Output: `envcloak run` of the emitter, approved from a terminal of
    /// the approver's: its marker must reach the model, no value in any
    /// form.
    fn output(&mut self) -> SurfaceProbe {
        let (Some(fixture), Some(_)) = (self.home.output.as_ref(), self.home.approver) else {
            let why = if self.home.approver.is_none() {
                vec![Reason::ProbeNeedsTerminal]
            } else {
                Vec::new()
            };
            return skipped(Surface::Output, Outcome::Skipped, &why);
        };
        // The host runs in the probe's directory, as every probe's run does,
        // so the probe context the result is kept for is the one it ran in
        // (Codex review of M2-09); the command goes to the project whose
        // manifest binds the values.
        let mut words = vec![
            "cd".to_owned(),
            shell_quote(&fixture.project.to_string_lossy()),
            "&&".to_owned(),
            shell_quote(&self.home.envcloak.to_string_lossy()),
            "run".to_owned(),
            "--wait".to_owned(),
            "120s".to_owned(),
            "--".to_owned(),
        ];
        words.extend(fixture.command.iter().map(|w| shell_quote(w)));
        let mut spec = self.spec(
            "output",
            json!({"steps": [{"shell": words.join(" ")}, {"say": "done"}]}),
            "Run the emitter through EnvCloak.".to_owned(),
        );
        if self.claude() {
            spec.probe = claude::permissions(&["Bash"]);
        } else {
            // What this surface measures is EnvCloak's redaction, not the
            // host's sandbox: the run must reach the daemon, which no
            // pinned Linux sandbox lets it (K-01).
            spec.sandbox = "danger-full-access";
        }
        spec.approve = true;
        let r = self.run(&spec);
        let ran = r.usable() && contains(r.after(1).as_bytes(), fixture.marker.as_bytes());
        let value_forms: Vec<Zeroizing<Vec<u8>>> = fixture
            .values
            .iter()
            .flat_map(|v| forms(v.as_slice()))
            .collect();
        let leaked = seen(&r.requests, &value_forms);
        surface(
            Surface::Output,
            vec![
                check(
                    "the emitter ran under envcloak run and its marker reached the model",
                    true,
                    ran,
                    "the covered run's output did not reach the model",
                ),
                check(
                    "no value reached the model in any form",
                    false,
                    !leaked,
                    "a value reached the model",
                ),
            ],
        )
    }

    /// EnvCloak's server: the host's own shell, in its sandbox, makes a
    /// write in the project (where the sandbox lets it) and is denied one
    /// beside the sentinel's in the probe home, then prints a marker,
    /// which must come back in its result: the witness that the shell ran
    /// (Codex F-133: without it a shell that never ran, refused by a hook
    /// or by a sandbox that cannot start, read as a denied write). Then a
    /// command `run_with_secrets` starts makes the sentinel's write. Each
    /// is a check of its own and kept with the result, so the outcome
    /// shown is the one the evidence supports
    /// (`coverage::ServerObserved::supported`).
    fn sentinel(&mut self) -> ServerProbe {
        let mut out = ServerProbe {
            outcome: Outcome::Skipped,
            sentinel: Sentinel::NotRun,
            control_ran: false,
            allowed_write: false,
            control_denied: false,
            checks: Vec::new(),
        };
        let (Some(project), Some(_)) = (self.home.sentinel_project.clone(), self.home.approver)
        else {
            return out;
        };
        let (Ok(nonce), Ok(ran)) = (marker("sentinel"), marker("ran")) else {
            out.outcome = Outcome::Failed;
            return out;
        };
        let dir = self.home.home.join(format!(".{nonce}"));
        if std::fs::DirBuilder::new().mode(0o700).create(&dir).is_err() {
            out.outcome = Outcome::Failed;
            return out;
        }
        let denied = dir.join("shell");
        let allowed = self.home.project.join(format!("{nonce}-ok"));
        let sentinel = dir.join("mcp");
        let (a, b) = halves(&ran);
        let shell = format!(
            "touch {}; touch {}; printf '%s%s\\n' '{a}' '{b}'",
            shell_quote(&denied.to_string_lossy()),
            shell_quote(&allowed.to_string_lossy())
        );
        let input = json!({
            "project_dir": project.to_string_lossy(),
            "argv": ["/usr/bin/touch", sentinel.to_string_lossy()],
        });
        let call = if self.claude() {
            claude::mcp_step("envcloak", "run_with_secrets", input)
        } else {
            codex::mcp_step("envcloak", "run_with_secrets", input)
        };
        let mut spec = self.spec(
            "sentinel",
            json!({"steps": [{"shell": shell}, call, {"say": "done"}]}),
            "Write the sentinels.".to_owned(),
        );
        if self.claude() {
            spec.probe = claude::permissions(&["Bash", "mcp__envcloak__run_with_secrets"]);
            spec.probe
                .extend(["--settings".to_owned(), claude::sandbox_settings()]);
        } else {
            spec.sandbox = "workspace-write";
            spec.probe = codex::sentinel_settings();
        }
        spec.approve = true;
        let r = self.run(&spec);
        let usable = r.usable();
        out.control_ran = usable && contains(r.after(1).as_bytes(), ran.as_bytes());
        drop(r);
        out.allowed_write = out.control_ran && allowed.exists();
        out.control_denied = out.allowed_write && !denied.exists();
        let _ = std::fs::remove_file(&allowed);
        let appeared = sentinel.exists();
        out.sentinel = if appeared {
            Sentinel::Appeared
        } else {
            Sentinel::Absent
        };
        out.checks = vec![
            check(
                "the host ran the probe to its end",
                true,
                usable,
                "the host's run did not finish cleanly",
            ),
            check(
                "the host's own shell ran the control",
                true,
                out.control_ran,
                "the shell's marker did not come back: the control did not run",
            ),
            check(
                "the host's own shell wrote where its sandbox lets it",
                true,
                out.allowed_write,
                "the shell's write in the project is not there: no denial can be told apart",
            ),
            check(
                "the host's own shell is denied the write beside the sentinel's",
                true,
                out.control_denied,
                "the host's sandbox let its shell write there, or the shell did not run",
            ),
            check(
                "a command run_with_secrets started made the write",
                false,
                appeared,
                "the sentinel did not appear",
            ),
        ];
        out.outcome = if out.checks.iter().all(|c| c.passed) {
            Outcome::Passed
        } else {
            Outcome::Failed
        };
        out
    }
}

/// Whether the probe home's flags can add a permission rule or a hook
/// the configuration read for the directory does not show (the class of
/// the verifier's round-3 finding, a refusal or a block counted as
/// EnvCloak's while another source could give it): Claude Code's
/// `--settings` (a file or JSON, which can hold both) and `--plugin-dir`;
/// Codex's `-c` settings of `hooks` or `plugins`. A refusal or a block in
/// the host's own words is then not known to be EnvCloak's.
fn flags_add_rules_or_hooks(host: Host, args: &[String]) -> bool {
    match host {
        Host::ClaudeCode => args.iter().any(|a| {
            ["--settings", "--plugin-dir"]
                .iter()
                .any(|f| a == f || a.starts_with(&format!("{f}=")))
        }),
        Host::Codex => codex::settings(args).iter().any(|(k, _)| {
            let k = k.trim_matches('"');
            ["hooks", "plugins"]
                .iter()
                .any(|t| k == *t || k.starts_with(&format!("{t}.")))
        }),
    }
}

/// The transcript surface from what the prompt probe and the sweep found:
/// `blocked`, the prompt probe passed; `known`, every store the host may
/// keep a prompt in was swept; `complete`, each was read whole;
/// `in_session`, the control was found in its session's file; `kept`, the
/// blocked token was found in a store. Its absence counts only after
/// every control passed, and a token kept after a block is
/// `persists_blocked_prompt`. The prompt history only the hosts'
/// interactive sessions write is not what this swept: its case is not run
/// (M2-26's interactive variant), and said so with the surface.
fn transcript(
    blocked: bool,
    known: bool,
    complete: bool,
    in_session: bool,
    kept: bool,
) -> SurfaceProbe {
    let mut out = surface(
        Surface::Transcript,
        vec![
            check(
                "the prompt was blocked",
                true,
                blocked,
                "the prompt probe did not pass",
            ),
            check(
                "every store the host may keep a prompt in is known",
                true,
                known,
                "a setting that can move one of the host's stores could not be read",
            ),
            check(
                "the host's stores were read whole",
                true,
                complete,
                "a store could not be read whole",
            ),
            check(
                "the control prompt is in its session's store",
                true,
                in_session,
                "the sweep did not find the control in its session's file",
            ),
            check(
                "the blocked prompt is in none of them",
                false,
                !kept,
                "the blocked prompt is kept in the host's stores",
            ),
        ],
    );
    out.persisted = blocked && kept;
    out.skipped = vec![Case::InteractiveHistory];
    out
}

/// The rule's case of a probe ([`Prober::file_read`]): the call of step
/// `n - 1`, one EnvCloak's own host rule covers, is refused, by that rule
/// (the host's refusal under it, named from a fixed list:
/// [`controls::rule_refusal`]) or by EnvCloak's hook (its marker).
/// What refused it is named in the check's `why` either way, from the
/// fixed list.
fn rule_check(r: &HostRun, n: usize, host: Host, ours: bool) -> Check {
    let name = "the call EnvCloak's host rule covers is refused";
    let result = r.after(n);
    let by = if !r.usable() {
        Err("no refusal of the call EnvCloak's host rule covers reached the model")
    } else if contains(result.as_bytes(), b"[envcloak:") {
        Ok("EnvCloak's hook, with its marker")
    } else {
        match controls::rule_refusal(host, &result) {
            // The host's words name no rule: with another rule there that
            // could give them, the refusal is not known to be EnvCloak's.
            Some(_) if !ours => Err("the host refused it under a rule not known to be EnvCloak's"),
            Some(by) => Ok(by),
            None => Err(unmarked(&result)),
        }
    };
    Check {
        name,
        control: false,
        passed: by.is_ok(),
        why: by.unwrap_or_else(|why| why),
    }
}

/// The checks of a two-step denial probe: step 0, the control, whose
/// result must hold `control`; step 1, the probe, whose result must hold
/// EnvCloak's marker for `reason`, while nothing recorded holds `kept`.
fn denial_checks(
    r: &HostRun,
    control: &str,
    reason: Denied,
    kept: &[Zeroizing<Vec<u8>>],
) -> Vec<Check> {
    let usable = r.usable();
    let ctl = usable && contains(r.after(1).as_bytes(), control.as_bytes());
    let result = r.after(2);
    let marked = usable && contains(result.as_bytes(), denial(reason).as_bytes());
    // A denial without the marker is a failed probe (M2-09); what gave
    // it is named from a fixed list.
    let unmarked_why = if usable {
        unmarked(&result)
    } else {
        "no denial with EnvCloak's marker reached the model"
    };
    let leaked = seen(&r.requests, kept);
    vec![
        check(
            "the control call runs and its result reaches the model",
            true,
            ctl,
            "the control's result did not reach the model",
        ),
        check(
            "the probe call is denied with EnvCloak's marker",
            false,
            marked,
            unmarked_why,
        ),
        check(
            "nothing it would have read reaches the model",
            false,
            !leaked,
            "what the call reads reached the model",
        ),
    ]
}

/// A program started in a session of its own, on a pseudo-terminal of its
/// own that is the session's controlling terminal (M2-28): the agent host a
/// probe runs. Its standard streams are as its command sets them; the
/// terminal is the session's only, so nothing the program or its commands
/// do shares a session or a terminal with this process or with any
/// approver this process starts (SPEC §10b, T9-3), and the session leads a
/// process group whose number is the program's pid, which stays its own
/// while it is unreaped (D-34).
///
/// The program also holds the terminal open, on a descriptor of its own
/// beyond its standard streams (the number it has here when it starts),
/// which its commands inherit: so the session keeps its terminal for as
/// long as any of it runs (macOS takes a session's terminal away once no
/// process has it open, measured on 26.4, and then sends no hang-up and
/// judges an approval from there as one with no terminal at all, not as
/// the requester's), and the terminal is the session's lifeline. This
/// process holds its other side, the master, which nothing else holds
/// (close-on-exec), and reads and drops what the session writes there, so
/// no write to the terminal blocks: when this process ends, however it
/// ends, `kill -9` included, or [`HostSession::hang_up`] is called, the
/// kernel hangs the terminal up, and the program (the session's leader)
/// and the process group in the terminal's foreground (the program's,
/// where its commands run) get SIGHUP (Codex review of M2-28: a runner
/// killed mid-run left the host and its commands running).
pub struct HostSession {
    pub child: std::process::Child,
    /// The thread that holds the master side and reads it, and its stop.
    terminal: Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)>,
}

impl std::fmt::Debug for HostSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostSession")
            .field("pid", &self.child.id())
            .finish_non_exhaustive()
    }
}

/// How long the master's reader waits between looks at its stop.
const TERMINAL_POLL: Duration = Duration::from_millis(50);

impl HostSession {
    /// Starts `cmd` in a new session on a new pseudo-terminal, which it
    /// holds open (see the type's documentation).
    ///
    /// # Errors
    /// When no pseudo-terminal can be opened, or the program cannot be
    /// started, or cannot make its session.
    pub fn spawn(mut cmd: Command) -> std::io::Result<HostSession> {
        use std::io::Read as _;
        use std::os::fd::AsFd as _;
        let pty = envcloak_sys::pty::open_pty(None, None)?;
        envcloak_sys::new_session_on_spawn(&mut cmd, Some(pty.slave.as_fd()))?;
        envcloak_sys::inherit_on_spawn(&mut cmd, pty.slave.as_fd())?;
        let child = cmd.spawn()?;
        // `cmd` holds copies of the slave side until it goes: the
        // terminal is then open in the session alone.
        drop(cmd);
        drop(pty.slave);
        let stop = Arc::new(AtomicBool::new(false));
        let master = std::fs::File::from(pty.master);
        let stopped = Arc::clone(&stop);
        let reader = std::thread::spawn(move || {
            let mut buf = Zeroizing::new([0u8; 4096]);
            while !stopped.load(Ordering::SeqCst) {
                match envcloak_sys::wait_readable(master.as_fd(), TERMINAL_POLL) {
                    Ok(false) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    // Something to read, or the session has closed every
                    // copy of its side (end of file, or EIO on Linux):
                    // then nothing is left to hang up, and the master goes.
                    Ok(true) => match (&master).read(&mut buf[..]) {
                        Ok(n) if n > 0 => {}
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        _ => break,
                    },
                    Err(_) => break,
                }
            }
            drop(master);
        });
        Ok(HostSession {
            child,
            terminal: Some((stop, reader)),
        })
    }

    /// Closes the terminal's master side, which hangs the session up:
    /// whatever of it is left gets SIGHUP. Waits at most a poll step.
    pub fn hang_up(&mut self) {
        if let Some((stop, reader)) = self.terminal.take() {
            stop.store(true, Ordering::SeqCst);
            let _ = reader.join();
        }
    }
}

impl Drop for HostSession {
    fn drop(&mut self) {
        self.hang_up();
    }
}

/// Reads a pipe to its end on a thread of its own, dropping what it reads
/// through a wiping buffer (the host is never left blocked on a full
/// pipe) after looking in it for each of `texts` ([`Watch`]); the receiver
/// says, when it is done, which were printed.
fn drain(
    pipe: Option<impl std::io::Read + Send + 'static>,
    texts: Vec<&'static str>,
) -> mpsc::Receiver<Vec<bool>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut watch = Watch::new(&texts);
        if let Some(mut p) = pipe {
            let mut buf = Zeroizing::new(vec![0u8; 64 * 1024]);
            loop {
                match p.read(&mut buf) {
                    Ok(n) if n > 0 => watch.feed(&buf[..n]),
                    _ => break,
                }
            }
        }
        let _ = tx.send(watch.found());
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::{Decision, Event, decide};
    use envcloak_core::SecretBuf;

    fn payload(host: Host, tool: &str, input: Value) -> SecretBuf {
        let v = match host {
            Host::ClaudeCode => json!({
                "session_id": "s", "transcript_path": "/t", "cwd": "/p",
                "permission_mode": "default", "hook_event_name": "PreToolUse",
                "tool_name": tool, "tool_input": input, "tool_use_id": "u",
            }),
            Host::Codex => json!({
                "session_id": "s", "transcript_path": null, "cwd": "/p",
                "hook_event_name": "PreToolUse", "model": "m", "turn_id": "t",
                "permission_mode": "bypassPermissions",
                "tool_name": tool, "tool_input": input, "tool_use_id": "u",
            }),
        };
        let bytes = serde_json::to_vec(&v).unwrap_or_default();
        let mut b = SecretBuf::with_capacity(bytes.len());
        b.extend(&bytes).unwrap_or_else(|_| panic!("payload"));
        b
    }

    /// The probes' calls are what EnvCloak's hook denies, for the reason
    /// whose marker the probe looks for, and their controls what it lets
    /// through: a probe that asked for a call the hook allows could never
    /// pass, and one whose control the hook denied never count.
    #[test]
    fn the_probe_calls_are_what_the_hook_denies() {
        let deny = |host, tool: &str, input: Value| {
            decide(host, Event::PreToolUse, &payload(host, tool, input))
        };
        for host in [Host::ClaudeCode, Host::Codex] {
            let dump = if host == Host::ClaudeCode {
                "printenv"
            } else {
                "env"
            };
            assert_eq!(
                deny(host, "Bash", json!({"command": dump})),
                Decision::Deny(Denied::EnvDump),
                "{host:?}"
            );
            assert_eq!(
                deny(
                    host,
                    "Bash",
                    json!({"command": "printf '%s%s\\n' 'ecp-' 'x'"})
                ),
                Decision::Allow
            );
            assert_eq!(
                deny(host, "mcp__ecprobe__read_file", json!({"path": ".env"})),
                Decision::Deny(Denied::EnvFile)
            );
            assert_eq!(
                deny(
                    host,
                    "mcp__ecprobe__echo",
                    json!({"text": "ecp-mc", "more": "p-1"})
                ),
                Decision::Allow
            );
        }
        assert_eq!(
            deny(Host::Codex, "Bash", json!({"command": "cat -- .env"})),
            Decision::Deny(Denied::EnvFile)
        );
        // The rule's cases: what EnvCloak's host rules cover, which the
        // hook denies too, so the case passes whichever answers first.
        assert_eq!(
            deny(Host::Codex, "Bash", json!({"command": "cat .env"})),
            Decision::Deny(Denied::EnvFile)
        );
        assert_eq!(
            deny(Host::Codex, "Bash", json!({"command": "printenv"})),
            Decision::Deny(Denied::EnvDump)
        );
        // Claude Code's hook case: a `.env` outside the working directory.
        assert_eq!(
            deny(
                Host::ClaudeCode,
                "Read",
                json!({"file_path": "/q/ecprobe-elsewhere/.env"})
            ),
            Decision::Deny(Denied::EnvFile)
        );
        assert_eq!(
            deny(Host::Codex, "Bash", json!({"command": "cat README.md"})),
            Decision::Allow
        );
        assert_eq!(
            deny(Host::ClaudeCode, "Read", json!({"file_path": "/p/.env"})),
            Decision::Deny(Denied::EnvFile)
        );
        assert_eq!(
            deny(
                Host::ClaudeCode,
                "Read",
                json!({"file_path": "/p/README.md"})
            ),
            Decision::Allow
        );
        let _ = Event::ALL;
    }

    /// The rule's case passes on a refusal the host gives under EnvCloak's
    /// own rule, or on EnvCloak's marker, and on nothing else: a generic
    /// denial, no result, a run that did not finish.
    ///
    /// Mutation checked: `rule_check` passing whatever the result
    /// (`passed: true`): the generic denial passes and this fails.
    #[test]
    fn a_rule_case_needs_a_known_refusal() {
        let req = |n: usize, out: &str| {
            let body = json!({"messages": [
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a",
                  "content": out}]},
            ]});
            Recorded {
                seq: n as u64,
                at_ms: 0,
                method: "POST".to_owned(),
                path: "/v1/messages".to_owned(),
                query: None,
                headers: Vec::new(),
                values: Vec::new(),
                forward: Zeroizing::new(Vec::new()),
                status: 200,
                answered: true,
                api: Some("messages".to_owned()),
                pick: Some(format!("step {n}")),
                body: Zeroizing::new(body.to_string().into_bytes()),
            }
        };
        let run = |out: &str, exit: Option<i32>| HostRun {
            requests: vec![req(3, out)],
            clean: true,
            exit,
            timed_out: false,
            approved: None,
            printed: Vec::new(),
        };
        for (host, out, exit, passed) in [
            (
                Host::ClaudeCode,
                "Permission to read /p/.env has been denied by your permission settings.",
                Some(0),
                true,
            ),
            (
                Host::ClaudeCode,
                "[envcloak:env_file] stopped",
                Some(0),
                true,
            ),
            (
                Host::Codex,
                "exec_command failed: CreateProcess { message: \"Rejected(\\\"`/bin/zsh -lc \
                 printenv` rejected: It prints environment variables, which can hold keys. Run a \
                 command that needs a key as `envcloak run -- <command>`, and use `envcloak ls` \
                 to see which keys exist.\\\")\" }",
                Some(0),
                true,
            ),
            (
                Host::Codex,
                "exec_command failed: rejected: by a rule of the person's own",
                Some(0),
                false,
            ),
            (Host::ClaudeCode, "Permission denied", Some(0), false),
            (
                Host::Codex,
                "Permission to read /p/.env has been denied by your permission settings.",
                Some(0),
                false,
            ),
            (Host::ClaudeCode, "", Some(0), false),
            (
                Host::ClaudeCode,
                "[envcloak:env_file] stopped",
                Some(1),
                false,
            ),
        ] {
            let c = rule_check(&run(out, exit), 3, host, true);
            assert_eq!(c.passed, passed, "{host:?} {out:?} {exit:?}: {c:?}");
            assert!(!c.why.is_empty());
        }
        // Where another rule could give the host's words, its refusal is
        // not EnvCloak's: Claude Code's names no rule (the verifier's
        // round-2 finding); EnvCloak's marker still is EnvCloak's.
        let claude_refusal =
            "Permission to read /p/.env has been denied by your permission settings.";
        let c = rule_check(&run(claude_refusal, Some(0)), 3, Host::ClaudeCode, false);
        assert!(!c.passed, "{c:?}");
        assert_eq!(
            c.why,
            "the host refused it under a rule not known to be EnvCloak's"
        );
        let c = rule_check(
            &run("[envcloak:env_file] stopped", Some(0)),
            3,
            Host::ClaudeCode,
            false,
        );
        assert!(c.passed, "{c:?}");
    }

    /// The transcript passes only with every control: the prompt blocked,
    /// every store known (Codex's round-3 review: a store a layer moved
    /// was never swept, and the probe passed), each read whole, the control
    /// in its session's file; a token kept after a block is
    /// `persists_blocked_prompt`; the interactive history's case is never
    /// passed, only named.
    ///
    /// Mutation checked: the `known` check dropped from `transcript`: the
    /// stores not all known pass and this fails.
    #[test]
    fn a_transcript_pass_needs_every_store_known_and_read() {
        let pass = transcript(true, true, true, true, false);
        assert_eq!(pass.outcome, Outcome::Passed);
        assert_eq!(pass.skipped, [Case::InteractiveHistory]);
        assert!(!pass.persisted);
        for (name, t) in [
            ("not blocked", transcript(false, true, true, true, false)),
            (
                "a store not known",
                transcript(true, false, true, true, false),
            ),
            (
                "a store not read whole",
                transcript(true, true, false, true, false),
            ),
            ("no control", transcript(true, true, true, false, false)),
        ] {
            assert_eq!(t.outcome, Outcome::Failed, "{name}");
            assert_eq!(t.skipped, [Case::InteractiveHistory], "{name}");
            assert_eq!(t.checks.iter().filter(|c| !c.passed).count(), 1, "{name}");
        }
        let kept = transcript(true, true, true, true, true);
        assert_eq!(kept.outcome, Outcome::Failed);
        assert!(kept.persisted);
        assert!(!transcript(false, true, true, true, true).persisted);
    }

    /// The home's flags that can add a rule or a hook the configuration
    /// read does not show make a refusal or a block in the host's words
    /// not EnvCloak's; other flags (the trust bypass CI pins) do not.
    ///
    /// Mutation checked: `flags_add_rules_or_hooks` answering false: the
    /// `--settings` and `-c hooks` cases fail and this fails.
    #[test]
    fn flags_that_add_rules_or_hooks_are_told_apart() {
        let v = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<String>>();
        for (host, args, adds) in [
            (Host::ClaudeCode, v(&["--settings", "/x.json"]), true),
            (Host::ClaudeCode, v(&["--settings={}"]), true),
            (Host::ClaudeCode, v(&["--plugin-dir", "/p"]), true),
            (Host::ClaudeCode, v(&["--model", "m"]), false),
            (Host::Codex, v(&["-c", "hooks.UserPromptSubmit=[]"]), true),
            (
                Host::Codex,
                v(&["--config", "plugins.\"x@y\".enabled=true"]),
                true,
            ),
            (Host::Codex, v(&["--dangerously-bypass-hook-trust"]), false),
            (Host::Codex, v(&["-c", "model=\"m\""]), false),
        ] {
            assert_eq!(
                flags_add_rules_or_hooks(host, &args),
                adds,
                "{host:?} {args:?}"
            );
        }
    }

    /// The `-c` settings of a home's flags that move Codex's stores are
    /// read as Codex reads them; a move this cannot place is not taken as
    /// known.
    #[test]
    fn codex_settings_in_flags_are_read() {
        let args: Vec<String> = [
            "--dangerously-bypass-hook-trust",
            "-c",
            "log_dir=\"/var/x/logs\"",
            "--config",
            "sqlite_home = '~/state'",
            "--config=log_dir=/plain/path",
            "-c",
            "model=\"m\"",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let got = codex::settings(&args);
        assert_eq!(
            got,
            [
                ("log_dir".to_owned(), "\"/var/x/logs\"".to_owned()),
                ("sqlite_home".to_owned(), "'~/state'".to_owned()),
                ("log_dir".to_owned(), "/plain/path".to_owned()),
                ("model".to_owned(), "\"m\"".to_owned()),
            ]
        );
        let home = Path::new("/h");
        assert_eq!(
            codex::setting_path("\"/var/x/logs\"", home),
            Some(PathBuf::from("/var/x/logs"))
        );
        assert_eq!(
            codex::setting_path("'~/state'", home),
            Some(PathBuf::from("/h/state"))
        );
        assert_eq!(
            codex::setting_path("/plain/path", home),
            Some(PathBuf::from("/plain/path"))
        );
        for unknown in ["\"logs\"", "3", "[\"/x\"]", "relative/path"] {
            assert_eq!(codex::setting_path(unknown, home), None, "{unknown}");
        }
    }

    /// The prompt probe's witness texts are what the pinned hosts print
    /// when EnvCloak's prompt hook blocks a prompt: Claude Code's is
    /// EnvCloak's own marker for the reason.
    #[test]
    fn the_block_witness_is_envcloaks_marker_on_claude_code() {
        assert_eq!(CLAUDE_BLOCKED, denial(Denied::KeyInPrompt));
        assert!(CODEX_BLOCKED.contains("UserPromptSubmit"));
    }

    /// Codex resumes a session with the sandbox as a setting (`exec
    /// resume` takes no `--sandbox`), the session's id before the prompt.
    #[test]
    fn a_codex_session_is_resumed_with_its_sandbox_as_a_setting() {
        let words: Vec<String> = codex::resume_args(
            "http://127.0.0.1:9",
            "0000-id",
            "the prompt",
            "read-only",
            &["-c".to_owned(), "x=1".to_owned()],
            &["--home-flag".to_owned()],
        )
        .into_iter()
        .map(|w| w.to_string_lossy().into_owned())
        .collect();
        assert_eq!(words[..2], ["exec", "resume"]);
        assert!(!words.iter().any(|w| w == "--sandbox"), "{words:?}");
        assert!(words.iter().any(|w| w == "sandbox_mode=\"read-only\""));
        assert_eq!(words[words.len() - 2..], ["0000-id", "the prompt"]);
        let fresh: Vec<String> =
            codex::args("http://127.0.0.1:9", "the prompt", "read-only", &[], &[])
                .into_iter()
                .map(|w| w.to_string_lossy().into_owned())
                .collect();
        assert_eq!(fresh[0], "exec");
        assert!(fresh.windows(2).any(|w| w == ["--sandbox", "read-only"]));
        assert_eq!(fresh.last().map(String::as_str), Some("the prompt"));
    }

    #[test]
    fn a_denial_needs_its_control_its_marker_and_no_leak() {
        let req = |n: usize, out: &str| {
            let body = json!({"messages": [
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a",
                  "content": out}]},
            ]});
            Recorded {
                seq: n as u64,
                at_ms: 0,
                method: "POST".to_owned(),
                path: "/v1/messages".to_owned(),
                query: None,
                headers: Vec::new(),
                values: Vec::new(),
                forward: Zeroizing::new(Vec::new()),
                status: 200,
                answered: true,
                api: Some("messages".to_owned()),
                pick: Some(format!("step {n}")),
                body: Zeroizing::new(body.to_string().into_bytes()),
            }
        };
        let kept = forms(b"ecp-envfile-1");
        let run = |reqs: Vec<Recorded>, exit: Option<i32>| HostRun {
            requests: reqs,
            clean: true,
            exit,
            timed_out: false,
            approved: None,
            printed: Vec::new(),
        };
        let marked = "[envcloak:env_file] stopped";
        let all_pass = |c: &[Check]| c.iter().all(|c| c.passed);
        let good = run(vec![req(1, "ecp-ctl"), req(2, marked)], Some(0));
        assert!(all_pass(&denial_checks(
            &good,
            "ecp-ctl",
            Denied::EnvFile,
            &kept
        )));
        // No control, a crash, a denial without the marker, a leak.
        for bad in [
            run(vec![req(1, "nothing"), req(2, marked)], Some(0)),
            run(vec![req(1, "ecp-ctl"), req(2, marked)], Some(1)),
            run(
                vec![req(1, "ecp-ctl"), req(2, "Permission denied")],
                Some(0),
            ),
            run(
                vec![
                    req(1, "ecp-ctl"),
                    req(2, &format!("{marked} ecp-envfile-1")),
                ],
                Some(0),
            ),
            run(vec![req(1, "ecp-ctl")], Some(0)),
            run(Vec::new(), Some(0)),
        ] {
            assert!(!all_pass(&denial_checks(
                &bad,
                "ecp-ctl",
                Denied::EnvFile,
                &kept
            )));
        }
    }

    /// A host session keeps its terminal while it runs (`ps` names one for
    /// it), and hanging it up ends the host and the command it runs in its
    /// process group, with no signal sent to either by this process (Codex
    /// review of M2-28: the runner's death left them running). Mutation
    /// checked: the terminal not held open in the session (`HostSession`
    /// without its `inherit_on_spawn`): on macOS the session then has no
    /// terminal, the hang-up reaches nobody, and this fails.
    #[test]
    fn a_host_session_keeps_its_terminal_and_its_hang_up_ends_it() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let pid_file = dir.path().join("pid");
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            &format!(
                "sleep 60 & echo $! >{}; wait",
                shell_quote(&pid_file.to_string_lossy())
            ),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        let mut session = HostSession::spawn(cmd).unwrap_or_else(|e| panic!("{e}"));
        let end = Instant::now() + Duration::from_secs(20);
        let sleeper = loop {
            if let Ok(p) = std::fs::read_to_string(&pid_file)
                && !p.trim().is_empty()
            {
                break p.trim().to_owned();
            }
            assert!(Instant::now() < end, "the command did not start");
            std::thread::sleep(Duration::from_millis(20));
        };
        let tty = Command::new("/bin/ps")
            .args(["-o", "tty=", "-p", &session.child.id().to_string()])
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        let tty = String::from_utf8_lossy(&tty.stdout).trim().to_owned();
        let has_tty = !tty.is_empty() && tty != "?" && tty != "??";
        session.hang_up();
        let end = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(s) = session.child.try_wait().unwrap_or_else(|e| panic!("{e}")) {
                break Some(s);
            }
            if Instant::now() > end {
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let sleeping = || {
            Command::new("/bin/kill")
                .args(["-0", &sleeper])
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        };
        let end = Instant::now() + Duration::from_secs(20);
        while sleeping() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        let left = sleeping();
        if status.is_none() {
            let _ = session.child.kill();
            let _ = session.child.wait();
        }
        if left {
            let _ = Command::new("/bin/kill").args(["-9", &sleeper]).status();
        }
        assert!(has_tty, "the session has no terminal: {tty:?}");
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            status.and_then(|s| s.signal()),
            Some(libc::SIGHUP),
            "the host outlived its session's hang-up"
        );
        assert!(!left, "its command outlived the hang-up");
    }
}
