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
//! When a host is not installed, [`require`] skips the test with a line
//! on standard error, unless `ENVCLOAK_TEST_REQUIRE_AGENT_HOSTS` is set
//! (CI's agent jobs set it), in which case the test fails.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
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

/// The cache: `ENVCLOAK_AGENT_HOSTS`, else `agent-hosts` in the target
/// directory of the running test binary.
pub fn cache_dir() -> PathBuf {
    if let Some(d) = std::env::var_os(CACHE_VAR) {
        return PathBuf::from(d);
    }
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("no current exe: {e}"));
    exe.parent()
        .and_then(Path::parent)
        .map(|t| t.join("agent-hosts"))
        .unwrap_or_else(|| panic!("the test binary is not in a target directory"))
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
            }
        })
        .collect()
}

/// A pinned host found installed and verified.
#[derive(Debug, Clone)]
pub struct Installed {
    pub pin: Pin,
    /// Its directory in the cache.
    pub dir: PathBuf,
    /// Its entry file.
    pub exe: PathBuf,
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
        let host = Installed { pin, dir, exe };
        host.verify()?;
        Ok(host)
    }

    /// Checks the entry file's SHA-256 against the pin again.
    ///
    /// # Errors
    /// When it is missing or differs.
    pub fn verify(&self) -> Result<(), String> {
        let got = sha256_file(&self.exe).map_err(|e| {
            format!(
                "{} {} is not installed ({e}); run {INSTALL}",
                self.pin.id, self.pin.version
            )
        })?;
        if got != self.pin.sha256 {
            return Err(format!(
                "{} at {} is not the pinned build (SHA-256 {got}); remove {} and run {INSTALL}",
                self.pin.id,
                self.exe.display(),
                self.dir.display()
            ));
        }
        Ok(())
    }
}

/// `found`, or `None` after saying why on standard error, unless
/// [`REQUIRE_VAR`] is set: then a host that is not there fails the test.
///
/// # Panics
/// As above.
pub fn require(found: Result<Installed, String>, test: &str) -> Option<Installed> {
    match found {
        Ok(h) => Some(h),
        Err(why) if std::env::var_os(REQUIRE_VAR).is_some() => {
            panic!("{test}: {why} ({REQUIRE_VAR} is set)")
        }
        Err(why) => {
            eprintln!("{test}: skipped: {why}");
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

/// One request the scripted model recorded. `Debug` leaves the body out.
#[derive(Clone)]
pub struct ModelRequest {
    pub seq: u64,
    pub at_ms: u64,
    pub method: String,
    pub path: String,
    pub status: u64,
    /// `messages`, `responses`, `hello` or `connect`.
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
            .field("path", &self.path)
            .field("status", &self.status)
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

    /// Complete, and every request one the script served: nothing
    /// unknown, refused, malformed or unscripted. Tunnels refused by the
    /// model ([`ModelReport::connects`]) do not count against it.
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
    /// order, refused.
    pub fn connects(&self) -> Vec<&str> {
        self.requests
            .iter()
            .filter(|r| r.api.as_deref() == Some("connect"))
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
    pub fn wait_for(&mut self, pick: &str, child: &mut Child) -> ModelRequest {
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
            if let Ok(Some(status)) = child.try_wait() {
                panic!("the host exited ({status}) before the model was asked for {pick}");
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
    codex_extra: String,
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
            codex_extra: String::new(),
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

    /// Sets a variable for every later host run, after the home's own
    /// (person-made settings, labelled so by the test).
    pub fn set_env(&mut self, name: &str, value: impl Into<OsString>) {
        self.env.retain(|(n, _)| n != name);
        self.env.push((name.to_owned(), value.into()));
    }

    /// TOML added to Codex's `config.toml` after the harness's own keys,
    /// for settings a test says the person made.
    pub fn codex_config(&mut self, toml: &str) {
        self.codex_extra = toml.to_owned();
    }

    /// The environment of a run against `model`: the home's cleared one,
    /// the host's model settings, the proxy, then the test's own.
    fn command(&self, exe: &Path, model: Option<&Model>) -> Command {
        let mut cmd = Command::new(exe);
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
                cmd.env("DISABLE_AUTOUPDATER", "1");
            }
            Host::Codex => {
                cmd.env("CODEX_HOME", self.codex_home());
            }
        }
        cmd.envs(self.env.iter().map(|(k, v)| (k, v)));
        cmd
    }

    /// The environment a run against `model` gets (see the module
    /// documentation), for a test that starts the host some other way,
    /// such as on a pseudo-terminal of its own.
    pub fn env_for(&self, model: &Model) -> Vec<(OsString, OsString)> {
        let cmd = self.command(&self.installed.exe, Some(model));
        cmd.get_envs()
            .filter_map(|(k, v)| Some((k.to_owned(), v?.to_owned())))
            .collect()
    }

    fn write_codex_config(&self, model: &Model) {
        let text = format!(
            "# Written by the EnvCloak test harness (M2-04): the scripted model is the\n\
             # only provider, and the update check is off.\n\
             model = \"ec-scripted\"\n\
             model_provider = \"ec\"\n\
             check_for_update_on_startup = false\n\
             model_providers.ec.name = \"EnvCloak scripted model\"\n\
             model_providers.ec.base_url = \"{}/v1\"\n\
             model_providers.ec.env_key = \"EC_MODEL_TOKEN\"\n\
             model_providers.ec.wire_api = \"responses\"\n\
             {}\n",
            model.base_url(),
            self.codex_extra
        );
        std::fs::write(self.codex_home().join("config.toml"), text)
            .unwrap_or_else(|e| panic!("write Codex's config.toml: {e}"));
    }

    /// Starts the host in `cwd` with `prompt` and `flags`, against a fresh
    /// scripted model running `script`, and returns while it runs.
    ///
    /// # Panics
    /// When the model or the host cannot start.
    pub fn spawn(&self, script: &Value, prompt: &str, flags: &HostFlags, cwd: &Path) -> Running {
        let model = Model::start(script);
        if self.host == Host::Codex {
            self.write_codex_config(&model);
        }
        let mut cmd = self.command(&self.installed.exe, Some(&model));
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
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("start {}: {e}", self.installed.pin.id));
        let collector = Collector::start(&mut child);
        Running {
            child,
            collector,
            model,
            start,
        }
    }

    /// [`AgentHome::spawn`], then [`Running::wait`]; then checks that the
    /// host is still the pinned build at the pinned version.
    ///
    /// # Panics
    /// When the host does not finish within [`RUN_LIMIT`], or changed.
    pub fn run(&self, script: &Value, prompt: &str, flags: &HostFlags, cwd: &Path) -> HostRun {
        let run = self.spawn(script, prompt, flags, cwd).wait();
        self.check_pinned();
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
        let mut cmd = self.command(&self.installed.exe, None);
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

/// A host run in progress ([`AgentHome::spawn`]).
#[derive(Debug)]
pub struct Running {
    pub child: Child,
    collector: Collector,
    pub model: Model,
    start: Instant,
}

impl Running {
    /// Waits for the host to exit (at most [`RUN_LIMIT`] from its start),
    /// then ends the model's run.
    ///
    /// # Panics
    /// When the host does not exit in time.
    pub fn wait(mut self) -> HostRun {
        let left = RUN_LIMIT.saturating_sub(self.start.elapsed());
        let output = self.collector.wait(&mut self.child, left);
        let elapsed = self.start.elapsed();
        HostRun {
            output,
            model: self.model.finish(),
            elapsed,
        }
    }
}

/// The output of a child, collected as it comes. What a descendant still
/// holds open after the child exits is collected for 5 more seconds, then
/// taken as it is.
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

    /// Waits up to `limit` for `child` (this process's own, unreaped
    /// child, killed if it is still running then) and returns its output.
    fn wait(&self, child: &mut Child, limit: Duration) -> Output {
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) => {}
                Err(e) => panic!("wait: {e}"),
            }
            if start.elapsed() > limit {
                let _ = child.kill();
                let _ = child.wait();
                panic!("a process did not exit within {limit:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let done = |c: &Collected| {
            c.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .1
        };
        let end = Instant::now() + Duration::from_secs(5);
        while !(done(&self.out) && done(&self.err)) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
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

/// Spawns `cmd` and waits up to `limit`, collecting its output as it
/// comes (see [`Collector`]). A process still running then is killed (it
/// is this function's own, unreaped child), and the test fails.
///
/// # Panics
/// As above, and when the process cannot start.
pub fn finish_within(mut cmd: Command, limit: Duration) -> Output {
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start a process: {e}"));
    let collector = Collector::start(&mut child);
    collector.wait(&mut child, limit)
}
