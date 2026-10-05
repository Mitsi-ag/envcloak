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
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::controls::{
    self, contains, denial, forms, halves, key_shaped, last_tool_output, marker, picked, reached,
    seen, unmarked,
};
use super::model::{self, ModelStub, Recorded};
use super::{
    Check, HostFlags, ProbeHome, ProbeHost, ProbeReport, RunSummary, ServerProbe, SurfaceProbe,
    claude, codex,
};
use crate::coverage::{Outcome, Reason, Sentinel, Surface};
use crate::hook::{Host, Reason as Denied};
use crate::hosts::shell_quote;
use crate::locations::Locations;

/// The proxy variables pointed at the model.
const PROXIES: [&str; 4] = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
/// How long the model may outlive the host's limit (its last report).
const MODEL_GRACE: Duration = Duration::from_secs(30);
/// The environment variable a shell probe looks for in the host's output.
const ENV_NAME: &str = "ECPROBE_ENV";

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
            control_denied: false,
            checks: Vec::new(),
        },
        runs: Vec::new(),
        flags: flags.args.clone(),
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
    };
    let fixtures = Fixtures::write(&home.project);
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
    }
}

/// The files a probe writes into its project: `README.md` holding a
/// marker (the read control), and `.env` holding another (what must never
/// reach the model); and a third marker for the host's environment (the
/// shell probe's).
struct Fixtures {
    readme: String,
    env_file: Zeroizing<String>,
    env_var: Zeroizing<String>,
}

impl Fixtures {
    fn write(project: &Path) -> std::io::Result<Fixtures> {
        let fx = Fixtures {
            readme: marker("readme")?,
            env_file: Zeroizing::new(marker("envfile")?),
            env_var: Zeroizing::new(marker("envvar")?),
        };
        write_file(
            &project.join("README.md"),
            format!("# Probe\n\n{}\n", fx.readme).as_bytes(),
        )?;
        let env = Zeroizing::new(format!("ECPROBE_FIXTURE={}\n", fx.env_file.as_str()));
        write_file(&project.join(".env"), env.as_bytes())?;
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
}

/// What one run left: the model's records (wiped on drop) and how the
/// host ended.
#[derive(Default)]
struct HostRun {
    requests: Vec<Recorded>,
    clean: bool,
    exit: Option<i32>,
    timed_out: bool,
    approved: Option<bool>,
}

impl HostRun {
    /// The run is evidence at all: the host exited 0 in time and the model
    /// served everything it was sent (a refused token, an unknown route, a
    /// malformed body, a cap reached all say the run is not one to read).
    fn usable(&self) -> bool {
        self.exit == Some(0) && !self.timed_out && self.clean
    }

    /// What the tool call of step `n - 1` returned, in the request that
    /// step `n` answered.
    fn after(&self, n: usize) -> Zeroizing<String> {
        picked(&self.requests, n).map_or_else(|| Zeroizing::new(String::new()), last_tool_output)
    }
}

struct Prober<'p, 'a> {
    host: &'p ProbeHost,
    home: &'p ProbeHome<'a>,
    flags: &'p HostFlags,
    runs: Vec<RunSummary>,
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
        }
    }

    /// Runs the host once as `spec` says.
    fn run(&mut self, spec: &Spec) -> HostRun {
        let start = Instant::now();
        let mut flags = spec.probe.clone();
        if !self.claude() {
            flags.extend(["--sandbox".to_owned(), spec.sandbox.to_owned()]);
        }
        flags.extend(self.flags.args.iter().cloned());
        let out = self.run_inner(spec, start);
        self.runs.push(RunSummary {
            name: spec.name,
            flags,
            exit: out.exit,
            timed_out: out.timed_out,
            requests: out.requests.len(),
            clean: out.clean,
            elapsed: start.elapsed(),
            approved: out.approved,
        });
        out
    }

    fn run_inner(&self, spec: &Spec, start: Instant) -> HostRun {
        let mut out = HostRun::default();
        let Ok(script) = serde_json::to_vec(&spec.script).map(Zeroizing::new) else {
            return out;
        };
        let Ok(stub) = ModelStub::start(
            &self.home.model_exe,
            &script,
            self.home.run_limit + MODEL_GRACE,
        ) else {
            return out;
        };
        let base = stub.base_url();
        let token = Zeroizing::new(stub.api_key().as_str().to_owned());
        let mut cmd = Command::new(&self.host.exe);
        cmd.env_clear()
            .envs(self.home.env.iter().map(|(k, v)| (k, v)));
        for k in PROXIES {
            cmd.env(k, &base);
        }
        for k in ["NO_PROXY", "no_proxy"] {
            cmd.env(k, "127.0.0.1,localhost");
        }
        let args = match self.host.host {
            Host::ClaudeCode => {
                cmd.envs(claude::model_env(&base, &token));
                claude::args(&spec.prompt, &spec.probe, &self.flags.args)
            }
            Host::Codex => {
                cmd.envs(codex::model_env(&token));
                codex::args(
                    &base,
                    &spec.prompt,
                    spec.sandbox,
                    &spec.probe,
                    &self.flags.args,
                )
            }
        };
        cmd.args(&args)
            .envs(spec.env.iter().map(|(k, v)| (k, v)))
            .current_dir(&spec.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let Ok(mut child) = cmd.spawn() else {
            drop(stub.finish());
            return out;
        };
        drop(args);
        let readers = [drain(child.stdout.take()), drain(child.stderr.take())];
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
        let left = (deadline + Duration::from_secs(5)).saturating_duration_since(Instant::now());
        for r in readers {
            let _ = r.recv_timeout(left);
        }
        out.timed_out = timed_out;
        out.exit = if timed_out {
            None
        } else {
            status.and_then(|s| s.code())
        };
        out.approved = approved;
        if let Ok(report) = stub.finish() {
            out.clean = report.outcome.clean();
            out.requests = report.requests;
        }
        out
    }

    /// The prompt guard and, from the same two runs, the transcript.
    fn prompt_and_transcript(&mut self) -> (SurfaceProbe, SurfaceProbe) {
        let (Ok(ctl), Ok(token)) = (marker("prompt"), key_shaped()) else {
            return (
                failed(Surface::PromptToModel, "no random bytes"),
                failed(Surface::Transcript, "no random bytes"),
            );
        };
        let script = json!({"steps": [{"say": "done"}]});
        let spec = self.spec(
            "prompt control",
            script.clone(),
            format!("Reply with one word. {ctl}"),
        );
        let c = self.run(&spec);
        let control = c.usable() && reached(&c.requests, &ctl);
        drop(c);
        let spec = self.spec(
            "prompt probe",
            script,
            format!("Deploy it with {} now.", token.as_str()),
        );
        let p = self.run(&spec);
        let token_forms = forms(token.as_bytes());
        let blocked = p.usable() && !seen(&p.requests, &token_forms);
        drop(p);
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
                    "a prompt holding a key-shaped token never reaches it",
                    false,
                    blocked,
                    "the token reached the model, or the run did not finish",
                ),
            ],
        );
        let ctl_forms = forms(ctl.as_bytes());
        let swept = controls::sweep(&self.stores(), &[&ctl_forms, &token_forms]);
        let (found_ctl, found_token) = (swept.found[0], swept.found[1]);
        let mut transcript = surface(
            Surface::Transcript,
            vec![
                check(
                    "the prompt was blocked",
                    true,
                    control && blocked,
                    "the prompt probe did not pass",
                ),
                check(
                    "the host's stores were read whole",
                    true,
                    swept.complete,
                    "a store could not be read whole",
                ),
                check(
                    "the control prompt is in the host's stores",
                    true,
                    found_ctl,
                    "the control is in none of the stores swept",
                ),
                check(
                    "the blocked prompt is in none of them",
                    false,
                    !found_token,
                    "the blocked prompt is kept in the host's stores",
                ),
            ],
        );
        transcript.persisted = control && blocked && found_token;
        (prompt, transcript)
    }

    /// The host's stores for a pasted or printed value (D-15), in the
    /// probe home.
    fn stores(&self) -> Vec<(PathBuf, Option<String>)> {
        let env = |k: &str| {
            self.home
                .env
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
        };
        let Ok(l) = Locations::new(&env) else {
            return Vec::new();
        };
        let label = if self.claude() {
            "Claude Code"
        } else {
            "Codex"
        };
        l.transcript_sources()
            .into_iter()
            .filter(|s| s.label.starts_with(label))
            .map(|s| (s.path, s.names))
            .collect()
    }

    /// File read: a control read, a read of `.env` that must be denied
    /// with EnvCloak's marker, and (Claude Code) the `@` mentions.
    ///
    /// Claude Code's `Read` names the files by the project's resolved
    /// path, the one the host's working directory is. Claude Code checks
    /// its deny rules against that before any hook runs, so the resolved
    /// path is refused by the `Read(**/.env*)` rule first, without
    /// EnvCloak's marker, while a path spelled through a link (on macOS
    /// `/tmp` is one, to `/private/tmp`) passes that check, reaches
    /// EnvCloak's hook first and meets the rule only after it (measured on
    /// 2.1.280). The probe makes the call as a session shown the project
    /// would.
    fn file_read(&mut self, fx: &Fixtures) -> SurfaceProbe {
        let Ok(project) = std::fs::canonicalize(&self.home.project) else {
            return failed(
                Surface::FileRead,
                "the probe's project could not be resolved",
            );
        };
        let (control_step, probe_step) = if self.claude() {
            (
                claude::read_step(&project.join("README.md")),
                claude::read_step(&project.join(".env")),
            )
        } else {
            (
                json!({"shell": "cat README.md"}),
                json!({"shell": "cat -- .env"}),
            )
        };
        let mut spec = self.spec(
            "file read",
            json!({"steps": [control_step, probe_step, {"say": "done"}]}),
            "Read the project's README and its .env file.".to_owned(),
        );
        if self.claude() {
            spec.probe = claude::permissions(&["Bash", "Read"]);
        }
        let r = self.run(&spec);
        let env_forms = forms(fx.env_file.as_bytes());
        let mut checks = denial_checks(&r, &fx.readme, Denied::EnvFile, &env_forms);
        drop(r);
        if self.claude() {
            checks.extend(self.mentions(fx, &env_forms));
        }
        surface(Surface::FileRead, checks)
    }

    /// Claude Code's `@` mentions: `@README.md` (whose content must
    /// arrive) and `@.env` (whose content must not), each prompt carrying a
    /// marker of its own that must arrive.
    fn mentions(&mut self, fx: &Fixtures, env_forms: &[Zeroizing<Vec<u8>>]) -> Vec<Check> {
        let (Ok(m1), Ok(m2)) = (marker("mention"), marker("mention")) else {
            return vec![check("mentions", true, false, "no random bytes")];
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
            return vec![check(
                "an @README.md mention reaches the model",
                true,
                false,
                "the control mention did not reach the model",
            )];
        }
        if !expanded {
            // A host that does not expand `@` mentions under `-p` leaves
            // that case to M2-26's interactive variant: skipped here, which
            // fails nothing and claims nothing.
            return vec![check(
                "the @ mention cases are skipped: the host does not expand them under -p",
                true,
                true,
                "",
            )];
        }
        let spec = self.spec(
            "mention probe",
            script,
            format!("Summarize @.env for me. {m2}"),
        );
        let b = self.run(&spec);
        let arrived = b.usable() && reached(&b.requests, &m2);
        let leaked = seen(&b.requests, env_forms);
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
        ]
    }

    /// Shell: a printed marker must reach the model; printing the
    /// environment must be denied with EnvCloak's marker, and a variable
    /// of the host's environment never reach it.
    fn shell(&mut self, fx: &Fixtures) -> SurfaceProbe {
        let Ok(ctl) = marker("shell") else {
            return failed(Surface::Shell, "no random bytes");
        };
        let (a, b) = halves(&ctl);
        let dump = if self.claude() { "printenv" } else { "env" };
        let mut spec = self.spec(
            "shell",
            json!({"steps": [
                {"shell": format!("printf '%s%s\\n' '{a}' '{b}'")},
                {"shell": dump},
                {"say": "done"},
            ]}),
            "Print a marker, then the environment.".to_owned(),
        );
        if self.claude() {
            spec.probe = claude::permissions(&["Bash", "Read"]);
        }
        spec.env = vec![(ENV_NAME.into(), fx.env_var.as_str().into())];
        let r = self.run(&spec);
        let env_forms = forms(fx.env_var.as_bytes());
        surface(
            Surface::Shell,
            denial_checks(&r, &ctl, Denied::EnvDump, &env_forms),
        )
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
        let mut words = vec![
            shell_quote(&self.home.envcloak.to_string_lossy()),
            "run".to_owned(),
            "--wait".to_owned(),
            "120s".to_owned(),
            "--".to_owned(),
        ];
        words.extend(fixture.command.iter().map(|w| shell_quote(w)));
        let project = fixture.project.clone();
        let mut spec = self.spec(
            "output",
            json!({"steps": [{"shell": words.join(" ")}, {"say": "done"}]}),
            "Run the emitter through EnvCloak.".to_owned(),
        );
        spec.cwd = project;
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

    /// EnvCloak's server: the host's own shell is denied a write in the
    /// probe home, and a command `run_with_secrets` starts makes it.
    fn sentinel(&mut self) -> ServerProbe {
        let mut out = ServerProbe {
            outcome: Outcome::Skipped,
            sentinel: Sentinel::NotRun,
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
        let control = dir.join("shell");
        let sentinel = dir.join("mcp");
        let (a, b) = halves(&ran);
        let shell = format!(
            "touch {}; printf '%s%s\\n' '{a}' '{b}'",
            shell_quote(&control.to_string_lossy())
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
        drop(r);
        out.control_denied = !control.exists();
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
                "the host's own shell is denied the write",
                true,
                out.control_denied,
                "the host's sandbox let its shell write there",
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

/// Reads a pipe to its end on a thread of its own, dropping what it reads
/// through a wiping buffer (the host is never left blocked on a full
/// pipe); the receiver says when it is done.
fn drain(pipe: Option<impl std::io::Read + Send + 'static>) -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Some(mut p) = pipe {
            let mut buf = Zeroizing::new(vec![0u8; 64 * 1024]);
            while matches!(p.read(&mut buf), Ok(n) if n > 0) {}
        }
        let _ = tx.send(());
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
}
