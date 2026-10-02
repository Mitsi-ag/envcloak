//! Real agent hosts in isolated homes, driven by the scripted model (M2
//! plan task M2-04, decision D-13).
//!
//! - [`Installed`]: a host pinned in crates/envcloak-e2e/agents/versions.toml
//!   and installed by scripts/install-agent-hosts.py into the cache
//!   outside every HOME ([`cache_dir`]). It is found only when the
//!   SHA-256 of its entry file equals the pin, before every run and after
//!   it, when `--version` must also still name the pinned version: a host
//!   that updated itself fails the test.
//! - [`Model`]: one run of `envcloak-probe-model` (crates/envcloak-agents),
//!   started over its pipes, with its report at the end.
//! - [`AgentHome`]: a [`TestHome`] set up for one host. Claude Code gets
//!   `ANTHROPIC_BASE_URL` and the run's token as `ANTHROPIC_API_KEY`;
//!   Codex gets the provider `model_providers.ec` in
//!   `$CODEX_HOME/config.toml` with the token in `EC_MODEL_TOKEN`. Both
//!   get `HTTPS_PROXY` pointed at the model, which refuses and records
//!   every tunnel, so a run shows anywhere else a host tried to reach
//!   (on Linux CI the hosts also run with loopback only). No developer or
//!   CI credential ever enters the home: the environment is cleared
//!   first.
//!
//! When no host has been installed on this machine (no cache directory),
//! [`require`] skips the test with a line on standard error, unless
//! `ENVCLOAK_TEST_REQUIRE_AGENT_HOSTS` is set (CI's agent jobs set it). A
//! cache that exists but lacks the pinned build fails the test: the
//! installer ran, so a host it should have put there is missing.
//!
//! Every process the harness starts for a host leads a process group of
//! its own ([`GroupChild`]). When it exits, or outlives its limit, what is
//! left of the group is killed while the leader is still unreaped, so its
//! descendants (MCP servers, commands) go with it; its output is then read
//! to the end, and output that a process outside the group still holds
//! open fails the run as incomplete instead of being cut short.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::home::TestHome;

/// Set in CI's agent jobs: a missing or mismatched host fails the test.
pub const REQUIRE_VAR: &str = "ENVCLOAK_TEST_REQUIRE_AGENT_HOSTS";
/// Where the installed hosts are, when not the default.
pub const CACHE_VAR: &str = "ENVCLOAK_AGENT_HOSTS";
/// How to install them.
pub const INSTALL: &str = "python3 scripts/install-agent-hosts.py";
/// How long one host run may take.
pub const RUN_LIMIT: Duration = Duration::from_secs(300);

/// The tier-1 hosts the scripted model drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// Claude Code, over Anthropic Messages.
    ClaudeCode,
    /// Codex CLI, over OpenAI Responses.
    Codex,
}

impl Host {
    /// Its id in versions.toml and the agent catalog.
    pub fn id(self) -> &'static str {
        match self {
            Host::ClaudeCode => "claude-code",
            Host::Codex => "codex",
        }
    }
}

/// `darwin-arm64` or `linux-x64`: the platforms versions.toml pins.
pub fn platform() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("linux", "x86_64") => Some("linux-x64"),
        _ => None,
    }
}

/// The cache: `ENVCLOAK_AGENT_HOSTS`, else [`default_cache_dir`] of the
/// running binary, which is where scripts/install-agent-hosts.py installs
/// by default (`<target>/agent-hosts`).
pub fn cache_dir() -> PathBuf {
    if let Some(d) = std::env::var_os(CACHE_VAR) {
        return PathBuf::from(d);
    }
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("no current exe: {e}"));
    default_cache_dir(&exe)
        .unwrap_or_else(|| panic!("the running binary is not in a target directory"))
}

/// `agent-hosts` in the target directory of the binary `exe`: a test
/// binary is in `<target>/<profile>/deps`, a program such as `ec-model` in
/// `<target>/<profile>`. The installer's default is the same directory
/// (`CARGO_TARGET_DIR`, else the workspace's `target/`), checked by
/// crates/envcloak-testkit/tests/agent_cache.rs.
pub fn default_cache_dir(exe: &Path) -> Option<PathBuf> {
    let mut profile = exe.parent()?;
    if profile.file_name().is_some_and(|n| n == "deps") {
        profile = profile.parent()?;
    }
    Some(profile.parent()?.join("agent-hosts"))
}

/// One host as versions.toml pins it, for this platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub id: String,
    pub variant: String,
    pub version: String,
    pub tier: i64,
    /// The entry file, relative to the host's directory in the cache.
    pub entry: String,
    /// The entry file's SHA-256, lower-case hex.
    pub sha256: String,
    /// The program that runs the entry file, when it is a script
    /// (`node`: the pinned Node.js in the cache, [`node_pin`]).
    pub interpreter: Option<String>,
    /// The program the entry starts in its turn, relative to the host's
    /// directory, and its SHA-256: checked like the entry.
    pub starts: Option<(String, String)>,
}

/// Every host versions.toml pins for this platform.
///
/// # Panics
/// When the file cannot be read or a host lacks a field.
pub fn pins(versions: &Path) -> Vec<Pin> {
    let text = std::fs::read_to_string(versions)
        .unwrap_or_else(|e| panic!("read {}: {e}", versions.display()));
    let doc: toml_edit::Document<String> = text
        .parse()
        .unwrap_or_else(|e| panic!("{} is not TOML: {e}", versions.display()));
    let Some(plat) = platform() else {
        return Vec::new();
    };
    let Some(hosts) = doc.get("host").and_then(|h| h.as_array_of_tables()) else {
        panic!("{} has no [[host]]", versions.display());
    };
    let field = |t: &toml_edit::Table, k: &str| -> Option<String> {
        let item = t.get(k)?;
        if let Some(s) = item.as_str() {
            return Some(s.to_owned());
        }
        item.as_table_like()?.get(plat)?.as_str().map(str::to_owned)
    };
    hosts
        .iter()
        .map(|t| {
            let need = |k: &str| field(t, k).unwrap_or_else(|| panic!("a host without {k}"));
            let starts = field(t, "starts").map(|path| {
                let sum = field(t, "starts_sha256")
                    .unwrap_or_else(|| panic!("a host whose `starts` has no starts_sha256"));
                (path, sum)
            });
            Pin {
                id: need("id"),
                variant: need("variant"),
                version: need("version"),
                tier: t
                    .get("tier")
                    .and_then(toml_edit::Item::as_integer)
                    .unwrap_or(0),
                entry: need("entry"),
                sha256: need("sha256"),
                interpreter: field(t, "interpreter"),
                starts,
            }
        })
        .collect()
}

/// The Node.js versions.toml pins (its `[node]` table) for this platform:
/// the version and the SHA-256 of its `bin/node`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePin {
    pub version: String,
    pub sha256: String,
}

/// The `[node]` pin for this platform, if versions.toml has one.
///
/// # Panics
/// When the file cannot be read, or the pin lacks a field.
pub fn node_pin(versions: &Path) -> Option<NodePin> {
    let text = std::fs::read_to_string(versions)
        .unwrap_or_else(|e| panic!("read {}: {e}", versions.display()));
    let doc: toml_edit::Document<String> = text
        .parse()
        .unwrap_or_else(|e| panic!("{} is not TOML: {e}", versions.display()));
    let node = doc.get("node")?.as_table_like()?;
    let plat = platform()?;
    let version = node.get("version")?.as_str()?.to_owned();
    let sha256 = node
        .get("sha256")
        .and_then(|t| t.as_table_like()?.get(plat)?.as_str().map(str::to_owned))
        .unwrap_or_else(|| panic!("the [node] pin has no sha256 for {plat}"));
    Some(NodePin { version, sha256 })
}

/// A pinned host found installed and verified.
#[derive(Debug, Clone)]
pub struct Installed {
    pub pin: Pin,
    /// Its directory in the cache.
    pub dir: PathBuf,
    /// Its entry file.
    pub exe: PathBuf,
    /// The interpreter that runs the entry, when it is a script: the
    /// pinned Node.js in the cache, and its pinned SHA-256.
    pub interpreter: Option<(PathBuf, String)>,
}

/// The SHA-256 of a file, lower-case hex.
///
/// # Errors
/// When it cannot be read.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().fold(String::new(), |mut s, b| {
        s.push_str(&format!("{b:02x}"));
        s
    }))
}

impl Installed {
    /// The host `id`/`variant` pinned in `versions`, found in the cache
    /// with its entry file's SHA-256 equal to the pin.
    ///
    /// # Errors
    /// Why it cannot be used: not pinned for this platform, not
    /// installed, or not the pinned build.
    pub fn find(versions: &Path, id: &str, variant: &str) -> Result<Installed, String> {
        let Some(plat) = platform() else {
            return Err("this platform has no pinned hosts".to_owned());
        };
        let Some(pin) = pins(versions)
            .into_iter()
            .find(|p| p.id == id && p.variant == variant)
        else {
            return Err(format!("{id}/{variant} is not pinned"));
        };
        let dir = cache_dir().join(format!("{id}-{variant}-{}-{plat}", pin.version));
        let exe = dir.join(&pin.entry);
        let interpreter = match pin.interpreter.as_deref() {
            None => None,
            Some("node") => {
                let Some(node) = node_pin(versions) else {
                    return Err(format!(
                        "{id}/{variant} runs under node, which is not pinned"
                    ));
                };
                let path = cache_dir()
                    .join(format!("node-{}-{plat}", node.version))
                    .join("bin")
                    .join("node");
                Some((path, node.sha256))
            }
            Some(other) => return Err(format!("{id}/{variant}: no pinned interpreter {other}")),
        };
        let host = Installed {
            pin,
            dir,
            exe,
            interpreter,
        };
        host.verify()?;
        Ok(host)
    }

    /// Checks the entry file's SHA-256 against the pin again, and those of
    /// the program it starts and of its interpreter, when the pin names
    /// them.
    ///
    /// # Errors
    /// When any is missing or differs.
    pub fn verify(&self) -> Result<(), String> {
        let mut files = vec![(self.exe.clone(), self.pin.sha256.as_str())];
        if let Some((path, sum)) = &self.pin.starts {
            files.push((self.dir.join(path), sum.as_str()));
        }
        if let Some((path, sum)) = &self.interpreter {
            files.push((path.clone(), sum.as_str()));
        }
        for (file, want) in files {
            let got = sha256_file(&file).map_err(|e| {
                format!(
                    "{} {} is not installed ({e}); run {INSTALL}",
                    self.pin.id, self.pin.version
                )
            })?;
            if got != want {
                return Err(format!(
                    "{} at {} is not the pinned build (SHA-256 {got}); remove {} and run {INSTALL}",
                    self.pin.id,
                    file.display(),
                    self.dir.display()
                ));
            }
        }
        Ok(())
    }

    /// The command that starts the host: its entry, or its pinned
    /// interpreter with the entry as the script.
    pub fn command(&self) -> Command {
        match &self.interpreter {
            None => Command::new(&self.exe),
            Some((node, _)) => {
                let mut cmd = Command::new(node);
                cmd.arg(&self.exe);
                cmd
            }
        }
    }
}

/// When process `pid` started, in the kernel's units, as the daemon records
/// a process instance (`envcloak_sys::process_start_time`); `None` when
/// there is no such process.
pub fn start_time(pid: u32) -> Option<u64> {
    let pid = i32::try_from(pid).ok()?;
    envcloak_sys::process_start_time(pid)
        .ok()
        .map(envcloak_sys::StartTime::raw)
}

/// `found`, or `None` after saying why on standard error when no host has
/// been installed on this machine ([`cache_dir`] does not exist) and
/// [`REQUIRE_VAR`] is not set. Otherwise a host that is not there fails
/// the test: the installer ran, or CI requires the hosts.
///
/// # Panics
/// As above.
pub fn require(found: Result<Installed, String>, test: &str) -> Option<Installed> {
    match found {
        Ok(h) => Some(h),
        Err(why) if std::env::var_os(REQUIRE_VAR).is_some() => {
            panic!("{test}: {why} ({REQUIRE_VAR} is set)")
        }
        Err(why) if platform().is_some() && cache_dir().exists() => {
            panic!(
                "{test}: {why} (the cache {} exists, so the installer ran)",
                cache_dir().display()
            )
        }
        Err(why) => {
            eprintln!(
                "{test}: skipped: {why}; no host is installed in {} ({INSTALL})",
                cache_dir().display()
            );
            None
        }
    }
}

/// `envcloak-probe-model` from the target directory of the running test
/// binary, refused when older than its sources.
///
/// # Panics
/// When it is missing or stale.
pub fn probe_model_exe() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("no current exe: {e}"));
    // A test binary is in <target>/<profile>/deps, a program such as
    // ec-model in <target>/<profile> itself.
    let dir = exe
        .parent()
        .map(|d| match d.file_name() {
            Some(n) if n == "deps" => d.parent().unwrap_or(d),
            _ => d,
        })
        .unwrap_or_else(|| panic!("the running binary is not in a target directory"));
    let path = dir.join("envcloak-probe-model");
    assert!(
        path.is_file(),
        "{} is missing: run the tests with --workspace, or cargo build -p envcloak-agents --bins",
        path.display()
    );
    crate::fresh::assert_fresh_or(
        &path,
        "envcloak-agents",
        "cargo build -p envcloak-agents --bins",
    );
    path
}

/// One request the scripted model recorded. `Debug` leaves the body out,
/// and shows the path only when it is an endpoint the model serves (else
/// its length): a path is whatever a host sent.
#[derive(Clone)]
pub struct ModelRequest {
    pub seq: u64,
    pub at_ms: u64,
    pub method: String,
    pub path: String,
    pub status: u64,
    /// Whether the reply was sent whole (a reply held on a barrier is
    /// recorded first, unanswered).
    pub answered: bool,
    /// `messages`, `responses`, `hello`, `connect` (a tunnel) or `proxy` (a
    /// request to forward; `path` is then the `host:port` it names).
    pub api: Option<String>,
    /// `step <n>`, `side`, `exhausted` or `mismatch`.
    pub pick: Option<String>,
    pub body: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for ModelRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelRequest")
            .field("seq", &self.seq)
            .field("at_ms", &self.at_ms)
            .field("method", &self.method)
            .field(
                "path",
                &match self.path.as_str() {
                    p @ ("/v1/messages" | "/v1/responses" | "/api/hello") => p.to_owned(),
                    p => format!("<{} bytes>", p.len()),
                },
            )
            .field("status", &self.status)
            .field("answered", &self.answered)
            .field("api", &self.api)
            .field("pick", &self.pick)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl ModelRequest {
    /// The body as JSON, when it is.
    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

/// A finished run of the scripted model.
#[derive(Debug, Clone)]
pub struct ModelReport {
    pub requests: Vec<ModelRequest>,
    /// The program's outcome object (crates/envcloak-agents
    /// `probe::model::Outcome`).
    pub outcome: Value,
}

impl ModelReport {
    fn count(&self, field: &str) -> u64 {
        self.outcome[field].as_u64().unwrap_or(u64::MAX)
    }

    /// Complete, and every request one the script served and answered:
    /// nothing unknown, refused, malformed, unscripted or unanswered.
    /// Tunnels refused by the model ([`ModelReport::connects`]) do not
    /// count against it.
    pub fn clean(&self) -> bool {
        self.outcome["incomplete"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && [
                "unknown",
                "bad_token",
                "bad_peer",
                "malformed",
                "mismatch",
                "exhausted",
                "busy",
                "unanswered",
            ]
            .iter()
            .all(|f| self.count(f) == 0)
    }

    /// The requests to one of the two model APIs.
    pub fn model_calls(&self) -> Vec<&ModelRequest> {
        self.requests
            .iter()
            .filter(|r| matches!(r.api.as_deref(), Some("messages" | "responses")))
            .collect()
    }

    /// Where the host tried to reach besides the model (`host:port`), in
    /// order, refused: tunnels and requests to forward, through the proxy
    /// the harness names.
    pub fn connects(&self) -> Vec<&str> {
        self.requests
            .iter()
            .filter(|r| matches!(r.api.as_deref(), Some("connect" | "proxy")))
            .map(|r| r.path.as_str())
            .collect()
    }

    /// The method and path of every request, for the endpoint record.
    pub fn endpoints(&self) -> Vec<String> {
        self.requests
            .iter()
            .map(|r| format!("{} {}", r.method, r.path))
            .collect()
    }

    /// The method and path of every request made to the model itself:
    /// none of [`ModelReport::connects`].
    pub fn model_endpoints(&self) -> Vec<String> {
        self.requests
            .iter()
            .filter(|r| !matches!(r.api.as_deref(), Some("connect" | "proxy")))
            .map(|r| format!("{} {}", r.method, r.path))
            .collect()
    }
}

/// One run of `envcloak-probe-model`, its own child: its input closing
/// ends the run. Dropped without [`Model::finish`], it is killed.
#[derive(Debug)]
pub struct Model {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    addr: String,
    token: Zeroizing<String>,
}

impl Model {
    /// Starts a run with `script` (see crates/envcloak-agents
    /// `probe::model::Script`).
    ///
    /// # Panics
    /// When the program does not start or refuses the script.
    pub fn start(script: &Value) -> Model {
        let mut child = Command::new(probe_model_exe())
            .args(["--time-limit", &RUN_LIMIT.as_secs().to_string()])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| panic!("start envcloak-probe-model: {e}"));
        let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            panic!("envcloak-probe-model has no pipes");
        };
        let mut line = Zeroizing::new(script.to_string().into_bytes());
        line.push(b'\n');
        stdin
            .write_all(&line)
            .and_then(|()| stdin.flush())
            .unwrap_or_else(|e| panic!("hand envcloak-probe-model its script: {e}"));
        let mut stdout = BufReader::new(stdout);
        let ready = read_line(&mut stdout);
        let ready: Value = serde_json::from_slice(&ready)
            .unwrap_or_else(|_| panic!("envcloak-probe-model refused the script"));
        let (Some(addr), Some(token)) = (ready["addr"].as_str(), ready["token"].as_str()) else {
            panic!("envcloak-probe-model did not say where it listens");
        };
        Model {
            addr: addr.to_owned(),
            token: Zeroizing::new(token.to_owned()),
            child,
            stdin: Some(stdin),
            stdout,
        }
    }

    /// `http://127.0.0.1:<port>`.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The run's token, the hosts' API key.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Every request recorded so far.
    ///
    /// # Panics
    /// When the program has gone or does not answer.
    pub fn requests(&mut self) -> ModelReport {
        let Some(stdin) = self.stdin.as_mut() else {
            panic!("the model's run has ended");
        };
        stdin
            .write_all(b"requests\n")
            .and_then(|()| stdin.flush())
            .unwrap_or_else(|e| panic!("ask envcloak-probe-model for its requests: {e}"));
        let line = read_line(&mut self.stdout);
        let v: Value = serde_json::from_slice(&line)
            .unwrap_or_else(|_| panic!("envcloak-probe-model wrote an unreadable report"));
        parse_report(&v)
    }

    /// Releases the barrier `name`: the step held on it is answered.
    ///
    /// # Panics
    /// When the program has gone.
    pub fn release(&mut self, name: &str) {
        let Some(stdin) = self.stdin.as_mut() else {
            panic!("the model's run has ended");
        };
        stdin
            .write_all(format!("release {name}\n").as_bytes())
            .and_then(|()| stdin.flush())
            .unwrap_or_else(|e| panic!("release a barrier: {e}"));
    }

    /// Waits until a request the script answered with `pick` (`step 1`,
    /// say) is recorded, and returns it. Each poll is a round trip to the
    /// program; `child` is the host, which must still be running.
    ///
    /// # Panics
    /// When the host exits first, or [`RUN_LIMIT`] passes.
    pub fn wait_for(&mut self, pick: &str, child: &mut GroupChild) -> ModelRequest {
        let end = Instant::now() + RUN_LIMIT;
        loop {
            if let Some(r) = self
                .requests()
                .requests
                .into_iter()
                .find(|r| r.pick.as_deref() == Some(pick))
            {
                return r;
            }
            if child.has_exited() {
                panic!("the host exited before the model was asked for {pick}");
            }
            assert!(
                Instant::now() < end,
                "no request for {pick} within {RUN_LIMIT:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Ends the run and returns its report.
    ///
    /// # Panics
    /// When the program does not report.
    pub fn finish(mut self) -> ModelReport {
        if let Some(mut stdin) = self.stdin.take() {
            let _ = stdin.write_all(b"stop\n").and_then(|()| stdin.flush());
        }
        loop {
            let line = read_line(&mut self.stdout);
            let v: Value = serde_json::from_slice(&line)
                .unwrap_or_else(|_| panic!("envcloak-probe-model wrote an unreadable report"));
            if v["final"] == Value::Bool(true) {
                let _ = self.child.wait();
                return parse_report(&v);
            }
        }
    }
}

impl Drop for Model {
    fn drop(&mut self) {
        drop(self.stdin.take());
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn read_line(r: &mut BufReader<ChildStdout>) -> Zeroizing<Vec<u8>> {
    let mut line = Zeroizing::new(Vec::new());
    match r.by_ref().take(64 << 20).read_until(b'\n', &mut line) {
        Ok(n) if n > 0 && line.last() == Some(&b'\n') => {
            line.pop();
            line
        }
        _ => panic!("envcloak-probe-model ended without a whole line"),
    }
}

fn parse_report(v: &Value) -> ModelReport {
    let text = |r: &Value, k: &str| r[k].as_str().map(str::to_owned);
    let requests = v["requests"]
        .as_array()
        .map(|rs| {
            rs.iter()
                .map(|r| ModelRequest {
                    seq: r["seq"].as_u64().unwrap_or(0),
                    at_ms: r["at_ms"].as_u64().unwrap_or(0),
                    method: text(r, "method").unwrap_or_default(),
                    path: text(r, "path").unwrap_or_default(),
                    status: r["status"].as_u64().unwrap_or(0),
                    answered: r["answered"].as_bool().unwrap_or(false),
                    api: text(r, "api"),
                    pick: text(r, "pick"),
                    body: Zeroizing::new(
                        STANDARD
                            .decode(r["body"].as_str().unwrap_or(""))
                            .unwrap_or_else(|_| panic!("a recorded body is not base64")),
                    ),
                })
                .collect()
        })
        .unwrap_or_default();
    ModelReport {
        requests,
        outcome: v["outcome"].clone(),
    }
}

/// The flags a step pins for its host (D-13): never a bypass mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFlags {
    pub args: Vec<String>,
}

impl HostFlags {
    /// `claude -p` with `--permission-mode <mode>` and, when not empty,
    /// `--allowedTools <tools>`.
    pub fn claude(permission_mode: &str, allowed_tools: &[&str]) -> HostFlags {
        let mut args = vec!["--permission-mode".to_owned(), permission_mode.to_owned()];
        if !allowed_tools.is_empty() {
            args.push("--allowedTools".to_owned());
            args.push(allowed_tools.join(","));
        }
        HostFlags { args }
    }

    /// `codex exec --sandbox <sandbox>` with `approval_policy` set.
    pub fn codex(sandbox: &str, approval: &str) -> HostFlags {
        HostFlags {
            args: vec![
                "--sandbox".to_owned(),
                sandbox.to_owned(),
                "-c".to_owned(),
                format!("approval_policy=\"{approval}\""),
            ],
        }
    }

    /// These flags and `extra`.
    pub fn with(mut self, extra: &[&str]) -> HostFlags {
        self.args.extend(extra.iter().map(|s| (*s).to_owned()));
        self
    }
}

/// What one host run did.
#[derive(Debug)]
pub struct HostRun {
    pub output: Output,
    pub model: ModelReport,
    /// Where the run's scripted model listened (`http://127.0.0.1:<port>`).
    pub model_url: String,
    pub elapsed: Duration,
}

impl HostRun {
    /// Standard output and error, for a failure message. Sweep them
    /// before showing them when a run could hold a value.
    pub fn text(&self) -> String {
        format!(
            "exit {:?}\n--- stdout\n{}--- stderr\n{}",
            self.output.status.code(),
            String::from_utf8_lossy(&self.output.stdout),
            String::from_utf8_lossy(&self.output.stderr)
        )
    }
}

/// A [`TestHome`] set up for one pinned host. See the module
/// documentation. It owns its home ([`AgentHome::start`]) or shares one a
/// harness keeps alive ([`AgentHome::within`]).
#[derive(Debug)]
pub struct AgentHome {
    owned: Option<TestHome>,
    root: PathBuf,
    vars: Vec<(&'static str, OsString)>,
    pub host: Host,
    pub installed: Installed,
    env: Vec<(String, OsString)>,
    /// The keys [`AgentHome::codex_config`] last set, to take out when it
    /// sets others.
    codex_extra: Vec<Vec<String>>,
    /// Every directory a host was started in, by its real path, for
    /// [`AgentHome::check_isolated`].
    cwds: std::sync::Mutex<Vec<PathBuf>>,
    /// Where Claude Code makes its per-user temporary directory when it
    /// ignores `CLAUDE_CODE_TMPDIR`: `/tmp` (a test points it elsewhere).
    /// Shared with every other run and with the person's own sessions, so
    /// the harness only looks there, never removes anything.
    shared_tmp: PathBuf,
}

impl AgentHome {
    /// A fresh home for `installed`, which must be `host`.
    ///
    /// # Panics
    /// When the home cannot be made.
    pub fn start(host: Host, installed: Installed) -> AgentHome {
        let home = TestHome::new();
        let mut a = AgentHome::within(&home, host, installed);
        a.owned = Some(home);
        a
    }

    /// The host set up in `home`, which the caller keeps alive for as
    /// long as this is used.
    ///
    /// # Panics
    /// When `installed` is another host, or `CODEX_HOME` cannot be made.
    pub fn within(home: &TestHome, host: Host, installed: Installed) -> AgentHome {
        assert_eq!(installed.pin.id, host.id(), "a host of another kind");
        let a = AgentHome {
            owned: None,
            root: home.root().to_path_buf(),
            vars: home.vars(),
            host,
            installed,
            env: Vec::new(),
            codex_extra: Vec::new(),
            cwds: std::sync::Mutex::new(Vec::new()),
            shared_tmp: PathBuf::from("/tmp"),
        };
        if host == Host::Codex {
            std::fs::create_dir_all(a.codex_home())
                .unwrap_or_else(|e| panic!("create CODEX_HOME: {e}"));
        }
        a
    }

    /// The test home's root (`/tmp/ecXXXXXX`).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `HOME`.
    pub fn home_dir(&self) -> PathBuf {
        self.root.join("home")
    }

    /// The home, when this owns it.
    pub fn test_home(&self) -> Option<&TestHome> {
        self.owned.as_ref()
    }

    /// `$CODEX_HOME`: `~/.codex` in the home.
    pub fn codex_home(&self) -> PathBuf {
        self.home_dir().join(".codex")
    }

    /// Where Claude Code makes its per-user temporary directory: the
    /// home's `tmp/`, by `CLAUDE_CODE_TMPDIR`. Without it, 2.1.280 makes
    /// it in `/tmp` whatever `TMPDIR` says, outside the home, where a
    /// running command's output then lands.
    pub fn claude_tmp(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Where this home's host stores are (see
    /// [`crate::transcripts::transcript_roots`]).
    pub fn host_dirs(&self) -> crate::transcripts::HostDirs {
        crate::transcripts::HostDirs {
            home: self.home_dir(),
            codex_home: self.codex_home(),
            claude_tmp: self.claude_tmp(),
        }
    }

    /// Notes `cwd` as a directory a host is started in, before it starts.
    ///
    /// # Panics
    /// When `cwd` is not inside the test root (the harness checks, and
    /// would name, only the test root's own paths), or when Claude Code's
    /// shared temporary directory for it or for `HOME` is already there:
    /// what the run makes there could then not be told from what was
    /// there before (another run's, a person's own session, a path whose
    /// name collapses to the same one), so the run is refused before the
    /// host starts.
    fn note_cwd(&self, cwd: &Path) {
        let root = std::fs::canonicalize(&self.root)
            .unwrap_or_else(|e| panic!("the test root {}: {e}", self.root.display()));
        let real = std::fs::canonicalize(cwd)
            .unwrap_or_else(|e| panic!("a host's directory {}: {e}", cwd.display()));
        assert!(
            real.starts_with(&root),
            "a host may start only inside its test root {}, not in {}",
            root.display(),
            real.display()
        );
        for dir in self.shared_tmp_dirs(&real) {
            match std::fs::symlink_metadata(&dir) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => panic!(
                    "{} is there before the host starts: what the run keeps outside its \
                     home could not be told from it",
                    dir.display()
                ),
                Err(e) => panic!("cannot tell whether {} is there: {e}", dir.display()),
            }
        }
        let mut cwds = self
            .cwds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !cwds.contains(&real) {
            cwds.push(real);
        }
    }

    /// Where Claude Code would keep a run's temporary files for a host
    /// started in `cwd` (a real path), and for `HOME`, had it ignored
    /// `CLAUDE_CODE_TMPDIR`: `<shared tmp>/claude-<uid>/<the directory's
    /// real path, with every character but a letter or digit as ->`. None
    /// for Codex.
    fn shared_tmp_dirs(&self, cwd: &Path) -> Vec<PathBuf> {
        if self.host != Host::ClaudeCode {
            return Vec::new();
        }
        let base = crate::transcripts::claude_tmp_dir(&self.shared_tmp);
        let home = self.home_dir();
        let home = std::fs::canonicalize(&home).unwrap_or(home);
        [cwd.to_path_buf(), home]
            .iter()
            .map(|c| {
                let slug: String = c
                    .to_string_lossy()
                    .chars()
                    .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
                    .collect();
                base.join(slug)
            })
            .collect()
    }

    /// Checks that the host kept nothing outside this home: no Claude Code
    /// temporary directory for any directory it was started in, or for
    /// `HOME`, under the shared `/tmp/claude-<uid>/` (the harness points
    /// `CLAUDE_CODE_TMPDIR` into the home; this is that the host honoured
    /// it). Each was absent when its run started
    /// ([`AgentHome::spawn`] refuses to start otherwise). What is found
    /// is left where it is, as evidence: the harness removes nothing
    /// outside the test root.
    ///
    /// # Panics
    /// When one is there.
    pub fn check_isolated(&self) {
        let cwds = self
            .cwds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for cwd in &cwds {
            for dir in self.shared_tmp_dirs(cwd) {
                assert!(
                    std::fs::symlink_metadata(&dir).is_err(),
                    "the host kept files outside its home, in {} (left there)",
                    dir.display()
                );
            }
        }
    }

    /// Sets a variable for every later host run, after the home's own
    /// (person-made settings, labelled so by the test).
    pub fn set_env(&mut self, name: &str, value: impl Into<OsString>) {
        self.env.retain(|(n, _)| n != name);
        self.env.push((name.to_owned(), value.into()));
    }

    /// Settings a test says the person made, merged into Codex's
    /// `config.toml` key by key, after taking out the ones the last call
    /// set. What Codex's own CLI wrote there (`codex mcp add`) and the
    /// harness's keys stay as they are.
    ///
    /// # Panics
    /// When `toml` is not TOML, sets one of the harness's keys, or the
    /// file cannot be read or written.
    pub fn codex_config(&mut self, toml: &str) {
        let extra: toml_edit::DocumentMut = toml
            .parse()
            .unwrap_or_else(|e| panic!("the person's Codex settings are not TOML: {e}"));
        let leaves = leaves(extra.as_table());
        for leaf in &leaves {
            assert!(
                !HARNESS_KEYS.contains(&leaf[0].as_str()),
                "the harness owns Codex's {}",
                leaf[0]
            );
        }
        let mut doc = self.read_codex_config();
        for leaf in &self.codex_extra {
            remove_leaf(doc.as_table_mut(), leaf);
        }
        for leaf in &leaves {
            set_leaf(doc.as_table_mut(), extra.as_table(), leaf);
        }
        self.codex_extra = leaves;
        self.write_codex_doc(&doc);
    }

    fn read_codex_config(&self) -> toml_edit::DocumentMut {
        match std::fs::read_to_string(self.codex_home().join("config.toml")) {
            Ok(text) => text
                .parse()
                .unwrap_or_else(|e| panic!("Codex's config.toml is not TOML: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml_edit::DocumentMut::new(),
            Err(e) => panic!("read Codex's config.toml: {e}"),
        }
    }

    fn write_codex_doc(&self, doc: &toml_edit::DocumentMut) {
        std::fs::write(self.codex_home().join("config.toml"), doc.to_string())
            .unwrap_or_else(|e| panic!("write Codex's config.toml: {e}"));
    }

    /// The environment of a run against `model`: the home's cleared one,
    /// the host's model settings, the proxy, then the test's own.
    fn command(&self, model: Option<&Model>) -> Command {
        let mut cmd = self.installed.command();
        cmd.env_clear().envs(self.vars.iter().map(|(k, v)| (k, v)));
        if let Some(m) = model {
            let proxy = m.base_url();
            for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
                cmd.env(k, &proxy);
            }
            for k in ["NO_PROXY", "no_proxy"] {
                cmd.env(k, "127.0.0.1,localhost");
            }
            match self.host {
                Host::ClaudeCode => {
                    cmd.env("ANTHROPIC_BASE_URL", m.base_url())
                        .env("ANTHROPIC_API_KEY", m.token());
                }
                Host::Codex => {
                    cmd.env("EC_MODEL_TOKEN", m.token());
                }
            }
        }
        match self.host {
            Host::ClaudeCode => {
                cmd.env("DISABLE_AUTOUPDATER", "1")
                    .env("CLAUDE_CODE_TMPDIR", self.claude_tmp());
            }
            Host::Codex => {
                cmd.env("CODEX_HOME", self.codex_home());
            }
        }
        cmd.envs(self.env.iter().map(|(k, v)| (k, v)));
        cmd
    }

    /// The environment a run against `model` in `cwd` gets (see the
    /// module documentation), for a test that starts the host some other
    /// way, such as on a pseudo-terminal of its own.
    pub fn env_for(&self, model: &Model, cwd: &Path) -> Vec<(OsString, OsString)> {
        self.note_cwd(cwd);
        let cmd = self.command(Some(model));
        cmd.get_envs()
            .filter_map(|(k, v)| Some((k.to_owned(), v?.to_owned())))
            .collect()
    }

    /// The harness's keys in Codex's `config.toml`: the scripted model as
    /// the only provider, the update check off. Everything else in the
    /// file (the person's settings, what Codex's CLI wrote) is kept.
    fn write_codex_config(&self, model: &Model) {
        let mut doc = self.read_codex_config();
        let t = doc.as_table_mut();
        t.insert("model", toml_edit::value("ec-scripted"));
        t.insert("model_provider", toml_edit::value("ec"));
        t.insert("check_for_update_on_startup", toml_edit::value(false));
        let mut ec = toml_edit::Table::new();
        ec.insert("name", toml_edit::value("EnvCloak scripted model"));
        ec.insert(
            "base_url",
            toml_edit::value(format!("{}/v1", model.base_url())),
        );
        ec.insert("env_key", toml_edit::value("EC_MODEL_TOKEN"));
        ec.insert("wire_api", toml_edit::value("responses"));
        let mut providers = toml_edit::Table::new();
        providers.set_implicit(true);
        providers.insert("ec", toml_edit::Item::Table(ec));
        t.insert("model_providers", toml_edit::Item::Table(providers));
        self.write_codex_doc(&doc);
    }

    /// Starts the host in `cwd` with `prompt` and `flags`, against a fresh
    /// scripted model running `script`, and returns while it runs.
    ///
    /// # Panics
    /// When the model or the host cannot start.
    pub fn spawn(&self, script: &Value, prompt: &str, flags: &HostFlags, cwd: &Path) -> Running {
        self.note_cwd(cwd);
        let model = Model::start(script);
        if self.host == Host::Codex {
            self.write_codex_config(&model);
        }
        let mut cmd = self.command(Some(&model));
        match self.host {
            Host::ClaudeCode => {
                cmd.arg("-p").arg(prompt).args(&flags.args);
            }
            Host::Codex => {
                cmd.args(["exec", "--skip-git-repo-check", "--strict-config"])
                    .args(&flags.args)
                    .arg(prompt);
            }
        }
        cmd.current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let start = Instant::now();
        let mut child = GroupChild::spawn(&mut cmd)
            .unwrap_or_else(|e| panic!("start {}: {e}", self.installed.pin.id));
        let collector = Collector::start(&mut child.child);
        Running {
            child,
            collector,
            model,
            start,
        }
    }

    /// [`AgentHome::spawn`], then [`Running::wait`]; then checks that the
    /// host is still the pinned build at the pinned version, and kept
    /// nothing outside the home ([`AgentHome::check_isolated`]).
    ///
    /// # Panics
    /// When the host does not finish within [`RUN_LIMIT`], changed, or
    /// kept files elsewhere.
    pub fn run(&self, script: &Value, prompt: &str, flags: &HostFlags, cwd: &Path) -> HostRun {
        let run = self.spawn(script, prompt, flags, cwd).wait();
        self.check_pinned();
        self.check_isolated();
        run
    }

    /// [`AgentHome::run`] for Claude Code in `HOME`.
    pub fn claude(&self, script: &Value, prompt: &str, flags: &HostFlags) -> HostRun {
        assert_eq!(self.host, Host::ClaudeCode);
        self.run(script, prompt, flags, &self.home_dir())
    }

    /// [`AgentHome::run`] for Codex in `HOME`.
    pub fn codex(&self, script: &Value, prompt: &str, flags: &HostFlags) -> HostRun {
        assert_eq!(self.host, Host::Codex);
        self.run(script, prompt, flags, &self.home_dir())
    }

    /// Runs the host's own command line (`claude mcp add-json ...`, say),
    /// with no model, in `HOME`.
    ///
    /// # Panics
    /// When it does not finish.
    pub fn host_cli(&self, args: &[&str]) -> Output {
        let mut cmd = self.command(None);
        cmd.args(args)
            .current_dir(self.home_dir())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        finish_within(cmd, RUN_LIMIT)
    }

    /// Checks that the host is still the pinned build and `--version`
    /// names the pinned version: no update happened.
    ///
    /// # Panics
    /// When it changed.
    pub fn check_pinned(&self) {
        if let Err(why) = self.installed.verify() {
            panic!("the host changed during the run: {why}");
        }
        let out = self.host_cli(&["--version"]);
        let shown = String::from_utf8_lossy(&out.stdout);
        assert!(
            shown.contains(&self.installed.pin.version),
            "{} --version says {shown:?}, pinned {}",
            self.installed.pin.id,
            self.installed.pin.version
        );
    }
}

/// A host run in progress ([`AgentHome::spawn`]). Dropped without
/// [`Running::wait`] (a test that failed half way), what is left of the
/// host's group is killed.
#[derive(Debug)]
pub struct Running {
    pub child: GroupChild,
    collector: Collector,
    pub model: Model,
    start: Instant,
}

impl Running {
    /// Waits for the host to exit (at most [`RUN_LIMIT`] from its start),
    /// kills what is left of its group, reads its output to the end, then
    /// ends the model's run.
    ///
    /// # Panics
    /// When the host does not exit in time, or its output is incomplete.
    pub fn wait(mut self) -> HostRun {
        let left = RUN_LIMIT.saturating_sub(self.start.elapsed());
        let output = self.collector.wait(&mut self.child, left);
        let elapsed = self.start.elapsed();
        let model_url = self.model.base_url();
        HostRun {
            output,
            model: self.model.finish(),
            model_url,
            elapsed,
        }
    }
}

/// A child that leads a process group of its own, as the harness starts
/// every host (M2 plan §6 rule 3, D-34). Its exit is seen without reaping
/// it (`waitid` with `WNOWAIT`, on a thread of its own), so the group is
/// signalled only while the child that leads it is unreaped and its id
/// cannot have been reused; it is reaped last. Dropped before then, its
/// group is killed and it is reaped.
#[derive(Debug)]
pub struct GroupChild {
    child: Child,
    pid: i32,
    exited: mpsc::Receiver<()>,
    seen_exit: bool,
    status: Option<ExitStatus>,
}

impl GroupChild {
    /// Starts `cmd` as the leader of a new process group.
    ///
    /// # Errors
    /// When it cannot start.
    pub fn spawn(cmd: &mut Command) -> std::io::Result<GroupChild> {
        cmd.process_group(0);
        let child = cmd.spawn()?;
        let pid = i32::try_from(child.id()).map_err(std::io::Error::other)?;
        let (tx, exited) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = envcloak_sys::wait_for_exit(pid);
            let _ = tx.send(());
        });
        Ok(GroupChild {
            child,
            pid,
            exited,
            seen_exit: false,
            status: None,
        })
    }

    /// Its process id, which is also its group's.
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Whether it has exited (it stays unreaped).
    pub fn has_exited(&mut self) -> bool {
        if !self.seen_exit && self.exited.try_recv().is_ok() {
            self.seen_exit = true;
        }
        self.seen_exit
    }

    /// Waits up to `limit` for it to exit; whether it did.
    fn wait_exit(&mut self, limit: Duration) -> bool {
        if !self.seen_exit {
            match self.exited.recv_timeout(limit) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => self.seen_exit = true,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
        self.seen_exit
    }

    /// Sends `sig` to every process in its group, only while it is
    /// unreaped.
    fn signal_group(&self, sig: i32) {
        if self.status.is_none() {
            let _ = envcloak_sys::signal_group(self.pid, sig);
        }
    }

    /// Kills what is left of its group, waits for it to exit and reaps it.
    fn finish(&mut self) -> ExitStatus {
        if let Some(s) = self.status {
            return s;
        }
        self.signal_group(libc::SIGKILL);
        if !self.seen_exit {
            let _ = self.exited.recv();
            self.seen_exit = true;
        }
        let status = self
            .child
            .wait()
            .unwrap_or_else(|e| panic!("reap a child: {e}"));
        self.status = Some(status);
        status
    }
}

impl Drop for GroupChild {
    fn drop(&mut self) {
        if self.status.is_none() {
            let _ = self.finish();
        }
    }
}

/// How long output may stay open after a child exited and its group was
/// killed before the run is incomplete: only a process outside the group
/// can still hold it then.
const OUTPUT_GRACE: Duration = Duration::from_secs(10);

/// The output of a child, collected as it comes, to its end.
#[derive(Debug)]
struct Collector {
    out: Collected,
    err: Collected,
}

type Collected = std::sync::Arc<std::sync::Mutex<(Vec<u8>, bool)>>;

impl Collector {
    fn start(child: &mut Child) -> Collector {
        fn collect(s: Option<Box<dyn Read + Send>>) -> Collected {
            let buf: Collected =
                std::sync::Arc::new(std::sync::Mutex::new((Vec::new(), s.is_none())));
            if let Some(mut s) = s {
                let into = std::sync::Arc::clone(&buf);
                std::thread::spawn(move || {
                    let mut chunk = [0u8; 8192];
                    loop {
                        let n = s.read(&mut chunk).unwrap_or(0);
                        let mut b = into
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if n == 0 {
                            b.1 = true;
                            return;
                        }
                        b.0.extend_from_slice(&chunk[..n]);
                    }
                });
            }
            buf
        }
        Collector {
            out: collect(
                child
                    .stdout
                    .take()
                    .map(|s| Box::new(s) as Box<dyn Read + Send>),
            ),
            err: collect(
                child
                    .stderr
                    .take()
                    .map(|s| Box::new(s) as Box<dyn Read + Send>),
            ),
        }
    }

    /// Waits up to `limit` for `child` to exit (past it: `SIGTERM` to its
    /// group, then `SIGKILL` 2 s later), kills what is left of its group,
    /// reaps it, and returns its output read to the end.
    ///
    /// # Panics
    /// When it did not exit within `limit`, or a process outside its
    /// group still holds its output open [`OUTPUT_GRACE`] later (the
    /// output would be cut short: the run is incomplete).
    fn wait(&self, child: &mut GroupChild, limit: Duration) -> Output {
        self.wait_grace(child, limit, OUTPUT_GRACE)
    }

    fn wait_grace(&self, child: &mut GroupChild, limit: Duration, grace: Duration) -> Output {
        let in_time = child.wait_exit(limit);
        if !in_time {
            child.signal_group(libc::SIGTERM);
            child.wait_exit(Duration::from_secs(2));
        }
        let status = child.finish();
        let done = |c: &Collected| {
            c.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .1
        };
        let end = Instant::now() + grace;
        while !(done(&self.out) && done(&self.err)) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        let complete = done(&self.out) && done(&self.err);
        assert!(in_time, "a process did not exit within {limit:?}");
        assert!(
            complete,
            "incomplete output: {grace:?} after the process exited and its group was killed, \
             a process outside the group still held its output open"
        );
        let take = |c: &Collected| {
            std::mem::take(
                &mut c
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0,
            )
        };
        Output {
            status,
            stdout: take(&self.out),
            stderr: take(&self.err),
        }
    }
}

/// Spawns `cmd` as the leader of a process group of its own and waits up
/// to `limit`, collecting its output to the end (see [`Collector`] and
/// [`GroupChild`]). A process still running then is stopped with its
/// group, and the test fails.
///
/// # Panics
/// As above, and when the process cannot start.
pub fn finish_within(mut cmd: Command, limit: Duration) -> Output {
    let mut child =
        GroupChild::spawn(&mut cmd).unwrap_or_else(|e| panic!("cannot start a process: {e}"));
    let collector = Collector::start(&mut child.child);
    collector.wait(&mut child, limit)
}

/// The harness's own top-level keys in Codex's `config.toml`.
const HARNESS_KEYS: [&str; 4] = [
    "model",
    "model_provider",
    "check_for_update_on_startup",
    "model_providers",
];

/// The paths of the values `table` sets: through its tables, down to a
/// value or an array of tables, which count whole.
fn leaves(table: &toml_edit::Table) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for (k, item) in table {
        match item {
            toml_edit::Item::Table(t) => {
                for mut leaf in leaves(t) {
                    leaf.insert(0, k.to_owned());
                    out.push(leaf);
                }
            }
            _ => out.push(vec![k.to_owned()]),
        }
    }
    out
}

/// Sets the value at `leaf` in `doc` to the one in `from`, making the
/// tables on the way.
fn set_leaf(doc: &mut toml_edit::Table, from: &toml_edit::Table, leaf: &[String]) {
    let (Some(first), rest) = (leaf.first(), leaf.get(1..).unwrap_or(&[])) else {
        return;
    };
    let Some(item) = from.get(first) else { return };
    if rest.is_empty() {
        doc.insert(first, item.clone());
        return;
    }
    let Some(sub_from) = item.as_table() else {
        return;
    };
    let entry = doc.entry(first).or_insert_with(|| {
        let mut t = toml_edit::Table::new();
        t.set_implicit(true);
        toml_edit::Item::Table(t)
    });
    let Some(sub) = entry.as_table_mut() else {
        panic!("Codex's config.toml has {first} as a value, not a table");
    };
    set_leaf(sub, sub_from, rest);
}

/// Takes the value at `leaf` out of `doc`, and the tables it leaves empty.
fn remove_leaf(doc: &mut toml_edit::Table, leaf: &[String]) {
    let (Some(first), rest) = (leaf.first(), leaf.get(1..).unwrap_or(&[])) else {
        return;
    };
    if rest.is_empty() {
        doc.remove(first);
        return;
    }
    let empty = match doc.get_mut(first).and_then(toml_edit::Item::as_table_mut) {
        Some(sub) => {
            remove_leaf(sub, rest);
            sub.is_empty()
        }
        None => false,
    };
    if empty {
        doc.remove(first);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// A descendant in the group still holding the output when the child
    /// exits is killed with the group, so the output ends at once.
    #[test]
    fn what_is_left_of_the_group_is_killed_and_the_output_read_to_its_end() {
        let start = Instant::now();
        let out = finish_within(
            sh("sleep 600 & echo started; echo to-stderr >&2"),
            Duration::from_secs(60),
        );
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(out.stdout, b"started\n");
        assert_eq!(out.stderr, b"to-stderr\n");
        assert!(start.elapsed() < OUTPUT_GRACE, "{:?}", start.elapsed());
    }

    /// Output a process outside the group still holds is not cut short
    /// in silence: the run fails as incomplete. The escaped process ends on
    /// its own two seconds later.
    #[test]
    fn output_held_open_from_outside_the_group_fails_the_run() {
        let python = [
            "/usr/bin/python3",
            "/usr/local/bin/python3",
            "/opt/homebrew/bin/python3",
        ]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .unwrap_or_else(|| panic!("python3 is needed"));
        // The shell exits only once the process has left its group: a
        // FIFO is the barrier.
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let fifo = dir.path().join("left");
        let mut cmd = sh(&format!(
            "mkfifo '{f}'; {python} -c 'import os, time; os.setsid(); os.write(3, b\"x\"); \
             os.close(3); time.sleep(3)' 3>'{f}' & read x < '{f}'; echo started",
            f = fifo.display()
        ));
        let mut child = GroupChild::spawn(&mut cmd).unwrap_or_else(|e| panic!("{e}"));
        let collector = Collector::start(&mut child.child);
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            collector.wait_grace(&mut child, Duration::from_secs(60), Duration::from_secs(1))
        }));
        let message = failed
            .err()
            .and_then(|p| p.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        assert!(message.starts_with("incomplete output"), "{message:?}");
    }

    /// Past its limit the child and its group are stopped, and the test
    /// fails.
    #[test]
    fn a_child_past_its_limit_is_stopped_with_its_group() {
        let start = Instant::now();
        let failed = std::panic::catch_unwind(|| {
            finish_within(sh("sleep 600 & sleep 600"), Duration::from_secs(1))
        });
        let message = failed
            .err()
            .and_then(|p| p.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        assert!(message.contains("did not exit within"), "{message:?}");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }

    /// Dropped while it runs (a test that failed half way), the child's
    /// group is killed: its output, held by both processes, ends.
    #[test]
    fn a_child_dropped_while_running_takes_its_group_with_it() {
        let mut cmd = sh("sleep 600 & sleep 600");
        let mut child = GroupChild::spawn(&mut cmd).unwrap_or_else(|e| panic!("{e}"));
        let mut stdout = child
            .child
            .stdout
            .take()
            .unwrap_or_else(|| panic!("no stdout"));
        // The drop and the end of the output, each on a thread of its own,
        // both within 10 s: a drop that waited for the child instead of
        // killing its group would take 600.
        let (tx, rx) = mpsc::channel();
        let dropped = tx.clone();
        std::thread::spawn(move || {
            drop(child);
            let _ = dropped.send("dropped");
        });
        std::thread::spawn(move || {
            let mut rest = Vec::new();
            let _ = stdout.read_to_end(&mut rest);
            let _ = tx.send("output ended");
        });
        for _ in 0..2 {
            assert!(
                rx.recv_timeout(Duration::from_secs(10)).is_ok(),
                "the drop did not stop the child and its group"
            );
        }
    }

    fn installed() -> Installed {
        let pin = Pin {
            id: "codex".to_owned(),
            variant: "native".to_owned(),
            version: "0".to_owned(),
            tier: 1,
            entry: "codex".to_owned(),
            sha256: String::new(),
            interpreter: None,
            starts: None,
        };
        Installed {
            pin,
            dir: PathBuf::from("/nonexistent"),
            exe: PathBuf::from("/nonexistent/codex"),
            interpreter: None,
        }
    }

    /// A host whose entry is a script runs only under the pinned
    /// interpreter: a node whose SHA-256 is not the pin's fails the check
    /// every run makes, like a changed entry.
    #[test]
    fn a_host_s_interpreter_is_checked_like_its_entry() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let entry = dir.path().join("cli.js");
        let node = dir.path().join("node");
        std::fs::write(&entry, b"console.log(1)").unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(&node, b"a node").unwrap_or_else(|e| panic!("{e}"));
        let sum = |p: &Path| sha256_file(p).unwrap_or_else(|e| panic!("{e}"));
        let mut host = installed();
        host.exe = entry.clone();
        host.pin.sha256 = sum(&entry);
        host.interpreter = Some((node.clone(), sum(&node)));
        assert_eq!(host.verify(), Ok(()));
        std::fs::write(&node, b"another node").unwrap_or_else(|e| panic!("{e}"));
        let why = host.verify().err().unwrap_or_default();
        assert!(why.contains("is not the pinned build"), "{why}");
        let mut cmd = host.command();
        assert_eq!(cmd.get_program(), node.as_os_str());
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), [entry.as_os_str()]);
        let _ = cmd.env_clear();
    }

    /// The person's settings are merged into what Codex's own CLI wrote,
    /// and the next call takes out the last one's keys and nothing else.
    #[test]
    fn codex_settings_merge_key_by_key_and_keep_what_the_cli_wrote() {
        let home = TestHome::new();
        let mut a = AgentHome::within(&home, Host::Codex, installed());
        let file = a.codex_home().join("config.toml");
        let cli = "[mcp_servers.fixture]\ncommand = \"/bin/echo\"\nargs = [\"a\"]\n";
        std::fs::write(&file, cli).unwrap_or_else(|e| panic!("{e}"));
        a.codex_config(
            "[mcp_servers.fixture]\ntool_timeout_sec = 60\n\
             [[hooks.PreToolUse]]\nhooks = [{ type = \"command\", command = \"x\" }]\n",
        );
        let read = |f: &Path| -> toml_edit::DocumentMut {
            std::fs::read_to_string(f)
                .unwrap_or_else(|e| panic!("{e}"))
                .parse()
                .unwrap_or_else(|e| panic!("{e}"))
        };
        let doc = read(&file);
        assert_eq!(
            doc["mcp_servers"]["fixture"]["command"].as_str(),
            Some("/bin/echo")
        );
        assert_eq!(
            doc["mcp_servers"]["fixture"]["tool_timeout_sec"].as_integer(),
            Some(60)
        );
        assert!(doc["hooks"]["PreToolUse"].is_array_of_tables());
        a.codex_config("[sandbox_workspace_write]\nnetwork_access = true\n");
        let doc = read(&file);
        assert_eq!(
            doc["mcp_servers"]["fixture"]["command"].as_str(),
            Some("/bin/echo")
        );
        assert!(
            doc["mcp_servers"]["fixture"]
                .get("tool_timeout_sec")
                .is_none()
        );
        assert!(doc.get("hooks").is_none(), "{doc}");
        assert_eq!(
            doc["sandbox_workspace_write"]["network_access"].as_bool(),
            Some(true)
        );
    }

    /// A Claude Code home whose shared temporary directory is `shared`
    /// (standing in for `/tmp`), in `home`, which the test keeps.
    fn claude_home(home: &TestHome) -> (AgentHome, PathBuf) {
        let mut host = installed();
        host.pin.id = "claude-code".to_owned();
        let mut a = AgentHome::within(home, Host::ClaudeCode, host);
        let shared = home.root().join("shared");
        std::fs::create_dir_all(&shared).unwrap_or_else(|e| panic!("{e}"));
        a.shared_tmp = shared.clone();
        (a, shared)
    }

    /// Claude Code's temporary directory for `dir` under `shared`.
    fn slug_dir(shared: &Path, dir: &Path) -> PathBuf {
        let real = std::fs::canonicalize(dir).unwrap_or_else(|e| panic!("{e}"));
        let slug: String = real
            .to_string_lossy()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        crate::transcripts::claude_tmp_dir(shared).join(slug)
    }

    fn refused(f: impl FnOnce()) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err()
    }

    /// A host is started only inside its test root (review F-99): a
    /// directory outside it, or a link inside it to one outside, is
    /// refused before the host starts; one inside is taken.
    #[test]
    fn a_host_is_started_only_inside_its_test_root() {
        let home = TestHome::new();
        let (a, _) = claude_home(&home);
        let inside = home.root().join("project");
        std::fs::create_dir_all(&inside).unwrap_or_else(|e| panic!("{e}"));
        let outside = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let link = home.root().join("link");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap_or_else(|e| panic!("{e}"));
        assert!(refused(|| a.note_cwd(outside.path())));
        assert!(refused(|| a.note_cwd(&link)));
        assert!(refused(|| a.note_cwd(Path::new("/"))));
        assert!(!refused(|| a.note_cwd(&inside)));
        a.check_isolated();
    }

    /// The harness never removes anything from the shared temporary
    /// directory (review F-99): a directory there before the host starts
    /// (another run's, a person's own session's) refuses the run, and is
    /// kept when the home is dropped.
    #[test]
    fn a_temporary_directory_there_before_the_run_refuses_it_and_is_kept() {
        let home = TestHome::new();
        let (a, shared) = claude_home(&home);
        let project = home.root().join("project");
        std::fs::create_dir_all(&project).unwrap_or_else(|e| panic!("{e}"));
        let theirs = slug_dir(&shared, &project);
        std::fs::create_dir_all(theirs.join("tasks")).unwrap_or_else(|e| panic!("{e}"));
        assert!(refused(|| a.note_cwd(&project)));
        drop(a);
        assert!(
            theirs.join("tasks").is_dir(),
            "a directory not the run's was removed"
        );
    }

    /// Paths whose names collapse to the same directory name (`a-b` and
    /// `a/b`) are not told apart: another owner's directory for one
    /// refuses a run in the other, and is kept (review F-99).
    #[test]
    fn a_colliding_temporary_directory_refuses_the_run_and_is_kept() {
        let home = TestHome::new();
        let (a, shared) = claude_home(&home);
        let mine = home.root().join("a-b");
        let other = home.root().join("a").join("b");
        for d in [&mine, &other] {
            std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(slug_dir(&shared, &mine), slug_dir(&shared, &other));
        let theirs = slug_dir(&shared, &other);
        std::fs::create_dir_all(&theirs).unwrap_or_else(|e| panic!("{e}"));
        assert!(refused(|| a.note_cwd(&mine)));
        drop(a);
        assert!(theirs.is_dir(), "another owner's directory was removed");
    }

    /// What a host kept in the shared temporary directory fails the run
    /// and is left there as evidence: dropping the home removes nothing
    /// outside the test root (review F-99). Nothing there passes.
    #[test]
    fn what_a_host_kept_outside_its_home_fails_the_run_and_is_left() {
        let home = TestHome::new();
        let (a, shared) = claude_home(&home);
        let project = home.root().join("project");
        std::fs::create_dir_all(&project).unwrap_or_else(|e| panic!("{e}"));
        a.note_cwd(&project);
        a.check_isolated();
        let kept = slug_dir(&shared, &project);
        std::fs::create_dir_all(kept.join("tasks")).unwrap_or_else(|e| panic!("{e}"));
        assert!(refused(|| a.check_isolated()));
        drop(a);
        assert!(kept.join("tasks").is_dir(), "the evidence was removed");
        // The same for HOME's own directory.
        let (b, shared) = claude_home(&home);
        let _ = std::fs::remove_dir_all(crate::transcripts::claude_tmp_dir(&shared));
        b.note_cwd(&project);
        std::fs::create_dir_all(slug_dir(&shared, &home.root().join("home")))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(refused(|| b.check_isolated()));
    }

    #[test]
    fn the_cache_is_in_the_target_directory_of_the_running_binary() {
        for (exe, want) in [
            (
                "/w/target/debug/deps/agent_hosts-0123",
                "/w/target/agent-hosts",
            ),
            ("/w/target/debug/ec-model", "/w/target/agent-hosts"),
            ("/t/release/deps/m2_story-9", "/t/agent-hosts"),
        ] {
            assert_eq!(
                default_cache_dir(Path::new(exe)),
                Some(PathBuf::from(want)),
                "{exe}"
            );
        }
    }
}
