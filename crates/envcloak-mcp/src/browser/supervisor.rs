//! Hosted browser supervisor (`envcloak mcp --browser-supervisor`, SPEC §7.6,
//! M2b decisions D-03, D-04, D-17, D-30, D-31, D-34, SI-16, and `cycle342`).
//!
//! Spawns and supervises the pinned `integrations/browser-helper/index.cjs`
//! child process over two separate channels:
//! - MCP stdio (`stdin`/`stdout`): carries only JSON-RPC `initialize`,
//!   `tools/list`, and allowlisted `tools/call` traffic.
//! - Private control socketpair: carries `create_context`, `inject_state`,
//!   `read_identity`, `publish`, and `close` commands bound to a single
//!   sign-in attempt generation.
//!
//! Direct execution of `envcloak mcp --browser-supervisor` outside `envcloakd`
//! is refused with exit code `125` (`not_started_by_daemon`). When the
//! supervisor process is under a tracer (`envcloak_sys::tracer_present`),
//! `inject_state` is refused with `traced` before any secret material is
//! exposed to the control channel.

use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::allowlist::ToolAllowlist;

/// Maximum JSON-RPC or control line size accepted by the supervisor.
pub const MAX_SUPERVISOR_LINE_BYTES: usize = 1024 * 1024;

/// Refusal token returned when `envcloak mcp --browser-supervisor` is invoked
/// directly rather than spawned by `envcloakd`.
pub const NOT_STARTED_BY_DAEMON: &str = "not_started_by_daemon";

/// Refusal token returned when `inject_state` is called while the supervisor
/// process is under a debugger/tracer.
pub const TRACED_REFUSAL: &str = "traced";

/// Fixed unavailable error thrown by the helper's context getter before
/// publication or after close.
pub const CONTEXT_NOT_PUBLISHED: &str = "sign_in_context_not_published";

/// Refusal token returned when a session scope includes undeclared domains,
/// origins, unsupported cookie formats, or cookies whose stored metadata
/// (`path`, `domain`, `httpOnly`, `secure`, `sameSite`) is rewritten on import.
pub const UNSUPPORTED_SESSION_SCOPE: &str = "unsupported_session_scope";

/// Refusal token returned when the D-31 identity check fails or mismatches.
pub const IDENTITY_UNVERIFIED: &str = "identity_unverified";

/// Refusal token returned when the session lease has been revoked or closed.
pub const GRANT_REVOKED: &str = "grant_revoked";

/// Environment variable set by `envcloakd` holding the inherited Unix socket
/// descriptor that proves the browser supervisor was started by the daemon.
pub const BROWSER_SUPERVISOR_FD_ENV: &str = "ENVCLOAK_BROWSER_SUPERVISOR_FD";

/// Diagnostic coverage/llvm environment variables forwarded to child processes.
const DIAGNOSTIC_VARS: &[&str] = &[
    "LLVM_PROFILE_FILE",
    "CARGO_LLVM_COV",
    "CARGO_LLVM_COV_SHOW_ENV",
    "CARGO_LLVM_COV_TARGET_DIR",
    "RUST_BACKTRACE",
];

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Errors returned by the hosted browser supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorError {
    /// The supervisor entrypoint was not started by `envcloakd`.
    NotStartedByDaemon,
    /// The supervisor process is under a tracer (`PT_DENY_ATTACH` / `TracerPid`).
    Traced,
    /// Declared session state violated scope or had cookie metadata rewritten.
    UnsupportedSessionScope(String),
    /// D-31 post-injection identity verification failed.
    IdentityUnverified(String),
    /// The bound generation did not match or a second generation was requested.
    GenerationMismatch(String),
    /// The grant lease has been revoked or closed.
    GrantRevoked,
    /// Runtime pin verification or child I/O failed.
    Runtime(String),
}

impl SupervisorError {
    /// Returns the canonical machine-readable reason string for this error.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotStartedByDaemon => NOT_STARTED_BY_DAEMON,
            Self::Traced => TRACED_REFUSAL,
            Self::UnsupportedSessionScope(_) => UNSUPPORTED_SESSION_SCOPE,
            Self::IdentityUnverified(_) => IDENTITY_UNVERIFIED,
            Self::GenerationMismatch(_) => "generation_mismatch",
            Self::GrantRevoked => GRANT_REVOKED,
            Self::Runtime(_) => "runtime_error",
        }
    }

    fn into_cli_failure(self) -> envcloak_client::fail::Failure {
        let msg = self.to_string();
        match self {
            Self::NotStartedByDaemon => {
                envcloak_client::fail::Failure::new(NOT_STARTED_BY_DAEMON, msg)
            }
            Self::Traced => envcloak_client::fail::Failure::new("traced", msg),
            Self::UnsupportedSessionScope(_)
            | Self::IdentityUnverified(_)
            | Self::GenerationMismatch(_)
            | Self::GrantRevoked
            | Self::Runtime(_) => envcloak_client::fail::Failure::new("run_failed", msg),
        }
    }
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotStartedByDaemon => f.write_str(NOT_STARTED_BY_DAEMON),
            Self::Traced => f.write_str(TRACED_REFUSAL),
            Self::UnsupportedSessionScope(msg) => {
                write!(f, "{UNSUPPORTED_SESSION_SCOPE}: {msg}")
            }
            Self::IdentityUnverified(msg) => write!(f, "{IDENTITY_UNVERIFIED}: {msg}"),
            Self::GenerationMismatch(msg) => write!(f, "generation_mismatch: {msg}"),
            Self::GrantRevoked => f.write_str(GRANT_REVOKED),
            Self::Runtime(msg) => write!(f, "runtime_error: {msg}"),
        }
    }
}

impl std::error::Error for SupervisorError {}

/// Pinned Node, browser-helper, and Chrome for Testing metadata from
/// `integrations/browser/versions.toml`.
#[derive(Debug, Clone)]
pub struct BrowserPins {
    pub node_version: String,
    pub node_sha256: String,
    pub helper_package: String,
    pub helper_version: String,
    pub playwright_version: String,
    pub helper_entry: String,
    pub helper_entry_sha256: String,
    pub core_bundle: String,
    pub core_bundle_sha256: String,
    pub chrome_version: String,
    pub chrome_revision: String,
    pub chrome_entry: String,
    pub chrome_sha256: String,
}

/// Verified paths to the pinned Node binary, browser-helper `node_modules`,
/// and Chrome for Testing executable.
#[derive(Debug, Clone)]
pub struct VerifiedBrowserRuntime {
    pub pins: BrowserPins,
    pub node_exe: PathBuf,
    pub helper_script: PathBuf,
    pub helper_modules: PathBuf,
    pub chrome_exe: PathBuf,
}

/// Secret-bearing cookie entry injected over the private control pipe.
#[derive(Clone)]
pub struct DeclaredSecretCookie {
    pub name: String,
    pub value: SecretString,
    pub domain: String,
    pub path: String,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<String>,
    pub format: Option<String>,
    pub device_bound: bool,
}

impl std::fmt::Debug for DeclaredSecretCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeclaredSecretCookie")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("http_only", &self.http_only)
            .field("secure", &self.secure)
            .field("same_site", &self.same_site)
            .finish()
    }
}

/// Secret-bearing `localStorage` key-value entry injected for an allowed origin.
#[derive(Clone)]
pub struct DeclaredSecretLocalStorageItem {
    pub name: String,
    pub value: SecretString,
}

impl std::fmt::Debug for DeclaredSecretLocalStorageItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeclaredSecretLocalStorageItem")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Secret-bearing origin storage entry injected over the private control pipe.
#[derive(Debug, Clone)]
pub struct DeclaredSecretOrigin {
    pub origin: String,
    pub local_storage: Vec<DeclaredSecretLocalStorageItem>,
}

/// Complete declared session state carrying `SecretString` values for cookies
/// and `localStorage` entries.
#[derive(Debug, Clone, Default)]
pub struct DeclaredSecretState {
    pub allowed_cookie_domains: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub cookies: Vec<DeclaredSecretCookie>,
    pub origins: Vec<DeclaredSecretOrigin>,
}

/// Options for starting a [`BrowserSupervisor`].
#[derive(Debug, Clone, Default)]
pub struct SupervisorOptions {
    pub host_resolver_rules: Option<String>,
    pub isolated_control: bool,
    /// Test-only hook to simulate an attached tracer on `inject_state`.
    pub simulate_traced: bool,
    /// Test-only hook to simulate a local context close failure (`cleanup_failed`).
    pub simulate_close_failure: bool,
}

/// Bounded response returned by the helper's `read_identity` control command.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct IdentityResponse {
    pub status: u16,
    pub body: String,
    pub truncated: bool,
}

/// Expected identity fields matched by the supervisor against [`IdentityResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExpectedIdentity {
    pub account: String,
    pub tenant: String,
    pub role: String,
}

/// Diagnostic counters reported by the helper over the control channel.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HelperStats {
    pub has_create_connection: bool,
    pub mcp_version: String,
    pub playwright_version: String,
    pub bound_generation: Option<String>,
    pub published: bool,
    pub closed: bool,
    pub getter_calls: u64,
    pub getter_refusals: u64,
    pub forwarded_calls: Vec<String>,
}

/// Verifies that the current process was started by `envcloakd` with a valid,
/// same-UID connected Unix domain socket in `ENVCLOAK_BROWSER_SUPERVISOR_FD`.
///
/// # Errors
/// Returns [`SupervisorError::NotStartedByDaemon`] if the environment variable
/// is absent, not a valid file descriptor, or not a connected same-UID socket.
pub fn verify_started_by_daemon() -> Result<OwnedFd, SupervisorError> {
    let raw_str =
        env::var(BROWSER_SUPERVISOR_FD_ENV).map_err(|_| SupervisorError::NotStartedByDaemon)?;
    let raw_fd: i32 = raw_str
        .trim()
        .parse()
        .map_err(|_| SupervisorError::NotStartedByDaemon)?;
    verify_started_by_daemon_fd(raw_fd)
}

/// Verifies that `raw_fd` (>= 3) is an inherited connected Unix domain socket
/// owned by the same effective UID as this process.
pub fn verify_started_by_daemon_fd(raw_fd: i32) -> Result<OwnedFd, SupervisorError> {
    if raw_fd < 3 {
        return Err(SupervisorError::NotStartedByDaemon);
    }
    let claimed = envcloak_sys::claim_inherited_fd(raw_fd)
        .map_err(|_| SupervisorError::NotStartedByDaemon)?;
    let peer = envcloak_sys::peer_identity(claimed.as_fd())
        .map_err(|_| SupervisorError::NotStartedByDaemon)?;
    let my_uid = envcloak_sys::effective_uid();
    if peer.uid != my_uid {
        return Err(SupervisorError::NotStartedByDaemon);
    }
    Ok(claimed)
}

/// Computes the lowercase hex SHA-256 digest of a file on disk.
pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    Ok(out)
}

/// Platform key used in `integrations/browser/versions.toml`.
#[must_use]
pub fn platform() -> Option<&'static str> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("darwin-arm64")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("darwin-x64")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("linux-x64")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("linux-arm64")
    } else {
        None
    }
}

/// Locates the workspace root containing `integrations/browser/versions.toml`.
pub fn repo_root() -> PathBuf {
    if let Ok(explicit) = env::var("ENVCLOAK_WORKSPACE_ROOT") {
        let p = PathBuf::from(explicit);
        if p.join("integrations/browser/versions.toml").is_file() {
            return p;
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

/// Default path to `integrations/browser/versions.toml`.
#[must_use]
pub fn browser_versions_path() -> PathBuf {
    repo_root().join("integrations/browser/versions.toml")
}

/// Cache directory for pinned agent and browser runtimes.
#[must_use]
pub fn cache_dir() -> PathBuf {
    if let Some(dir) = env::var_os("ENVCLOAK_AGENT_HOSTS") {
        return PathBuf::from(dir);
    }
    if let Ok(exe) = env::current_exe()
        && let Some(mut profile) = exe.parent()
    {
        if profile.file_name().is_some_and(|n| n == "deps")
            && let Some(parent) = profile.parent()
        {
            profile = parent;
        }
        if let Some(target_dir) = profile.parent() {
            let candidate = target_dir.join("agent-hosts");
            if candidate.is_dir() {
                return candidate;
            }
        }
    }
    repo_root().join("target/agent-hosts")
}

/// Reads [`BrowserPins`] for the current platform from `versions_toml`.
pub fn read_browser_pins(versions_toml: &Path) -> Result<BrowserPins, String> {
    let plat = platform().ok_or_else(|| "unsupported platform for browser pins".to_owned())?;
    let text = fs::read_to_string(versions_toml)
        .map_err(|e| format!("read {}: {e}", versions_toml.display()))?;
    let doc: toml_edit::Document<String> = text
        .parse()
        .map_err(|e| format!("parse {}: {e}", versions_toml.display()))?;

    let str_in = |table: &str, key: &str| -> Result<String, String> {
        doc.get(table)
            .and_then(|t| t.as_table_like())
            .and_then(|t| t.get(key))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| format!("missing [{table}].{key} in {}", versions_toml.display()))
    };

    let plat_in = |table: &str, sub: &str| -> Result<String, String> {
        doc.get(table)
            .and_then(|t| t.as_table_like())
            .and_then(|t| t.get(sub))
            .and_then(|t| t.as_table_like())
            .and_then(|t| t.get(plat))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| {
                format!(
                    "missing [{table}.{sub}].{plat} in {}",
                    versions_toml.display()
                )
            })
    };

    Ok(BrowserPins {
        node_version: str_in("node", "version")?,
        node_sha256: plat_in("node", "sha256")?,
        helper_package: str_in("browser_helper", "package")?,
        helper_version: str_in("browser_helper", "version")?,
        playwright_version: str_in("browser_helper", "playwright_version")?,
        helper_entry: str_in("browser_helper", "entry")?,
        helper_entry_sha256: str_in("browser_helper", "entry_sha256")?,
        core_bundle: str_in("browser_helper", "core_bundle")?,
        core_bundle_sha256: str_in("browser_helper", "core_bundle_sha256")?,
        chrome_version: str_in("chrome_for_testing", "version")?,
        chrome_revision: str_in("chrome_for_testing", "revision")?,
        chrome_entry: plat_in("chrome_for_testing", "entry")?,
        chrome_sha256: plat_in("chrome_for_testing", "sha256")?,
    })
}

/// Verifies a Chrome for Testing executable against `expected_sha256` and
/// checks that `com.apple.quarantine` is absent on macOS.
pub fn verify_chrome_executable(chrome_exe: &Path, expected_sha256: &str) -> Result<(), String> {
    let got = sha256_file(chrome_exe).map_err(|e| {
        format!(
            "chrome_for_testing missing at {}: {e}",
            chrome_exe.display()
        )
    })?;
    if got != expected_sha256 {
        return Err(format!(
            "chrome_for_testing_hash_mismatch: {} has SHA-256 {got}, expected {expected_sha256}",
            chrome_exe.display()
        ));
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("/usr/bin/xattr")
            .arg("-l")
            .arg(chrome_exe)
            .output()
            .map_err(|e| format!("xattr check failed: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("com.apple.quarantine") {
            return Err(format!(
                "chrome_for_testing_quarantined: {} carries com.apple.quarantine",
                chrome_exe.display()
            ));
        }
    }
    Ok(())
}

/// Resolves the Node.js binary and verifies its SHA-256 against `pins` when
/// the pinned cache entry exists.
pub fn resolve_node_binary(pins: &BrowserPins) -> Result<PathBuf, String> {
    let plat = platform().ok_or_else(|| "unsupported platform".to_owned())?;
    if let Some(env_node) = env::var_os("ENVCLOAK_NODE_BIN") {
        let node_exe = PathBuf::from(env_node);
        let got_node = sha256_file(&node_exe)
            .map_err(|e| format!("ENVCLOAK_NODE_BIN missing at {}: {e}", node_exe.display()))?;
        if got_node != pins.node_sha256 {
            return Err(format!(
                "node_hash_mismatch: {} has SHA-256 {got_node}, expected {}",
                node_exe.display(),
                pins.node_sha256
            ));
        }
        return Ok(node_exe);
    }

    let pinned_exe = cache_dir()
        .join(format!("node-{}-{plat}", pins.node_version))
        .join("bin/node");
    if pinned_exe.is_file() || env::var_os("ENVCLOAK_REQUIRE_BROWSER_RUNTIME").is_some() {
        let got_node = sha256_file(&pinned_exe)
            .map_err(|e| format!("pinned Node missing at {}: {e}", pinned_exe.display()))?;
        if got_node != pins.node_sha256 {
            return Err(format!(
                "node_hash_mismatch: {} has SHA-256 {got_node}, expected {}",
                pinned_exe.display(),
                pins.node_sha256
            ));
        }
        return Ok(pinned_exe);
    }

    if let Some(path_os) = env::var_os("PATH") {
        for dir in env::split_paths(&path_os) {
            let cand = dir.join("node");
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
    for fallback in [
        "/opt/homebrew/bin/node",
        "/usr/local/bin/node",
        "/usr/bin/node",
    ] {
        let cand = PathBuf::from(fallback);
        if cand.is_file() {
            return Ok(cand);
        }
    }

    Err(format!(
        "pinned Node missing at {} and no node found on PATH",
        pinned_exe.display()
    ))
}

/// Finds and verifies the pinned Node runtime, `@playwright/mcp` helper
/// modules, and Chrome for Testing executable against `versions_toml`.
pub fn resolve_browser_runtime(versions_toml: &Path) -> Result<VerifiedBrowserRuntime, String> {
    let pins = read_browser_pins(versions_toml)?;
    let plat = platform().ok_or_else(|| "unsupported platform".to_owned())?;
    let node_exe = resolve_node_binary(&pins)?;

    let root = repo_root();
    let helper_dir = root.join("integrations/browser-helper");
    let helper_script = helper_dir.join("index.cjs");
    if !helper_script.is_file() {
        return Err(format!("missing {}", helper_script.display()));
    }

    let mut module_candidates = Vec::new();
    if let Some(env_dir) = env::var_os("ENVCLOAK_BROWSER_HELPER_NODE_MODULES") {
        module_candidates.push(PathBuf::from(env_dir));
    }
    if let Some(env_dir) = env::var_os("ENVCLOAK_BROWSER_HELPER_MODULES") {
        module_candidates.push(PathBuf::from(env_dir));
    }
    module_candidates.push(helper_dir.join("node_modules"));
    module_candidates.push(
        cache_dir()
            .join(format!("browser-helper-{}-{plat}", pins.helper_version))
            .join("node_modules"),
    );
    module_candidates.push(cache_dir().join("browser-helper").join("node_modules"));

    let mut verified_modules = None;
    let mut last_mod_err = String::from("no browser-helper node_modules candidate found");
    for cand in module_candidates {
        if !cand.is_dir() {
            continue;
        }
        let parent = cand.parent().unwrap_or(&cand);
        let entry_path = parent.join(&pins.helper_entry);
        let bundle_path = parent.join(&pins.core_bundle);
        let mcp_pkg_path = cand.join("@playwright/mcp/package.json");
        let pw_pkg_path = cand.join("playwright/package.json");
        let Ok(entry_sum) = sha256_file(&entry_path) else {
            last_mod_err = format!("cannot read {}", entry_path.display());
            continue;
        };
        let Ok(bundle_sum) = sha256_file(&bundle_path) else {
            last_mod_err = format!("cannot read {}", bundle_path.display());
            continue;
        };
        if entry_sum != pins.helper_entry_sha256 {
            last_mod_err = format!(
                "{} SHA-256 {entry_sum} != {}",
                entry_path.display(),
                pins.helper_entry_sha256
            );
            continue;
        }
        if bundle_sum != pins.core_bundle_sha256 {
            last_mod_err = format!(
                "{} SHA-256 {bundle_sum} != {}",
                bundle_path.display(),
                pins.core_bundle_sha256
            );
            continue;
        }
        let mcp_ver = fs::read(&mcp_pkg_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v.get("version").and_then(Value::as_str).map(str::to_owned));
        let pw_ver = fs::read(&pw_pkg_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v.get("version").and_then(Value::as_str).map(str::to_owned));
        if mcp_ver.as_deref() != Some(pins.helper_version.as_str())
            || pw_ver.as_deref() != Some(pins.playwright_version.as_str())
        {
            last_mod_err = format!(
                "version mismatch in {}: mcp={mcp_ver:?}, playwright={pw_ver:?}",
                cand.display()
            );
            continue;
        }
        verified_modules = Some(cand);
        break;
    }
    let helper_modules = verified_modules.ok_or(last_mod_err)?;

    let mut chrome_candidates = Vec::new();
    if let Some(env_chrome) = env::var_os("ENVCLOAK_CHROME_FOR_TESTING_BIN") {
        chrome_candidates.push(PathBuf::from(env_chrome));
    }
    if let Some(env_chrome) = env::var_os("ENVCLOAK_CHROME_FOR_TESTING") {
        chrome_candidates.push(PathBuf::from(env_chrome));
    }
    if let Some(pw_path) = env::var_os("PLAYWRIGHT_BROWSERS_PATH") {
        chrome_candidates.push(
            PathBuf::from(pw_path)
                .join(format!("chromium-{}", pins.chrome_revision))
                .join(&pins.chrome_entry),
        );
    }
    chrome_candidates.push(
        cache_dir()
            .join(format!("chrome-for-testing-{}-{plat}", pins.chrome_version))
            .join(&pins.chrome_entry),
    );
    if let Some(home) = env::var_os("HOME") {
        let home_dir = PathBuf::from(home);
        chrome_candidates.push(
            home_dir
                .join("Library/Caches/ms-playwright")
                .join(format!("chromium-{}", pins.chrome_revision))
                .join(&pins.chrome_entry),
        );
        chrome_candidates.push(
            home_dir
                .join(".cache/ms-playwright")
                .join(format!("chromium-{}", pins.chrome_revision))
                .join(&pins.chrome_entry),
        );
    }

    let found_chrome = chrome_candidates
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| {
            format!(
                "Chrome for Testing {} (revision {}) not found in cache",
                pins.chrome_version, pins.chrome_revision
            )
        })?;

    verify_chrome_executable(&found_chrome, &pins.chrome_sha256)?;

    Ok(VerifiedBrowserRuntime {
        pins,
        node_exe,
        helper_script,
        helper_modules,
        chrome_exe: found_chrome,
    })
}

fn create_private_scratch_dir() -> Result<PathBuf, String> {
    let base = env::temp_dir();
    let pid = std::process::id();
    for _ in 0..64 {
        let seq = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = base.join(format!("ec-bsup-{pid}-{seq}"));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        if builder.create(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err("unable to create private scratch directory for browser helper".to_owned())
}

/// Production hosted browser supervisor (SPEC §7.6, M2b-08).
///
/// Spawns one `integrations/browser-helper` process per generation with a
/// cleared environment and pinned Node binary, bounds messages, filters
/// `tools/list` and `tools/call` through [`ToolAllowlist`], checks the
/// grant/lease before forwarding every allowed tool call, and refuses
/// `inject_state` with `traced` when under a debugger/tracer.
pub struct BrowserSupervisor {
    child: Child,
    mcp_in: ChildStdin,
    mcp_out: BufReader<ChildStdout>,
    ctrl_write: UnixStream,
    ctrl_read: BufReader<UnixStream>,
    next_id: u64,
    lease_active: Arc<AtomicBool>,
    simulate_traced: bool,
    simulate_close_failure: bool,
    bound_generation: Option<String>,
    published: bool,
    scratch_dir: PathBuf,
}

impl std::fmt::Debug for BrowserSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserSupervisor")
            .field("pid", &self.child.id())
            .field("lease_active", &self.lease_active.load(Ordering::SeqCst))
            .field("bound_generation", &self.bound_generation)
            .field("published", &self.published)
            .finish()
    }
}

impl BrowserSupervisor {
    /// Starts a supervisor and helper process using the default
    /// `integrations/browser/versions.toml`.
    pub fn start(opts: SupervisorOptions) -> Result<Self, SupervisorError> {
        Self::start_with_versions(&browser_versions_path(), opts)
    }

    /// Starts a supervisor after verifying pins in `versions_toml`.
    pub fn start_with_versions(
        versions_toml: &Path,
        opts: SupervisorOptions,
    ) -> Result<Self, SupervisorError> {
        let runtime = resolve_browser_runtime(versions_toml).map_err(SupervisorError::Runtime)?;
        Self::start_with_runtime(&runtime, opts)
    }

    /// Starts a supervisor using an already-verified [`VerifiedBrowserRuntime`].
    pub fn start_with_runtime(
        runtime: &VerifiedBrowserRuntime,
        opts: SupervisorOptions,
    ) -> Result<Self, SupervisorError> {
        verify_chrome_executable(&runtime.chrome_exe, &runtime.pins.chrome_sha256)
            .map_err(SupervisorError::Runtime)?;

        let scratch_dir = create_private_scratch_dir().map_err(SupervisorError::Runtime)?;
        let home_dir = scratch_dir.join("home");
        let tmp_dir = scratch_dir.join("tmp");
        let out_dir = scratch_dir.join("out");
        fs::create_dir_all(&home_dir)
            .map_err(|e| SupervisorError::Runtime(format!("mkdir home: {e}")))?;
        fs::create_dir_all(&tmp_dir)
            .map_err(|e| SupervisorError::Runtime(format!("mkdir tmp: {e}")))?;
        fs::create_dir_all(&out_dir)
            .map_err(|e| SupervisorError::Runtime(format!("mkdir out: {e}")))?;

        let (ctrl_parent, ctrl_child) =
            UnixStream::pair().map_err(|e| SupervisorError::Runtime(format!("socketpair: {e}")))?;
        ctrl_parent
            .set_read_timeout(Some(Duration::from_secs(20)))
            .map_err(|e| SupervisorError::Runtime(format!("set_read_timeout: {e}")))?;
        ctrl_parent
            .set_write_timeout(Some(Duration::from_secs(20)))
            .map_err(|e| SupervisorError::Runtime(format!("set_write_timeout: {e}")))?;
        let ctrl_parent_read = ctrl_parent
            .try_clone()
            .map_err(|e| SupervisorError::Runtime(format!("clone control socket: {e}")))?;

        let child_fd_num = ctrl_child.as_raw_fd();
        let mut cmd = Command::new(&runtime.node_exe);
        cmd.env_clear();
        cmd.env("HOME", &home_dir);
        cmd.env("TMPDIR", &tmp_dir);
        cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        for var in DIAGNOSTIC_VARS {
            if let Some(val) = env::var_os(var) {
                cmd.env(var, val);
            }
        }
        cmd.arg(&runtime.helper_script)
            .arg("--modules")
            .arg(&runtime.helper_modules)
            .arg("--chrome")
            .arg(&runtime.chrome_exe)
            .arg("--output-dir")
            .arg(&out_dir)
            .arg("--control-fd")
            .arg(child_fd_num.to_string());
        if let Some(rules) = &opts.host_resolver_rules {
            cmd.arg("--host-rules").arg(rules);
        }
        if opts.isolated_control {
            cmd.arg("--isolated-control");
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        envcloak_sys::inherit_on_spawn(&mut cmd, ctrl_child.as_fd())
            .map_err(|e| SupervisorError::Runtime(format!("inherit_on_spawn: {e}")))?;

        let mut child = cmd
            .spawn()
            .map_err(|e| SupervisorError::Runtime(format!("spawn browser-helper: {e}")))?;
        drop(cmd);
        drop(ctrl_child);

        let mcp_in = child
            .stdin
            .take()
            .ok_or_else(|| SupervisorError::Runtime("missing helper stdin".to_owned()))?;
        let mcp_out = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| SupervisorError::Runtime("missing helper stdout".to_owned()))?,
        );

        Ok(Self {
            child,
            mcp_in,
            mcp_out,
            ctrl_write: ctrl_parent,
            ctrl_read: BufReader::new(ctrl_parent_read),
            next_id: 1,
            lease_active: Arc::new(AtomicBool::new(true)),
            simulate_traced: opts.simulate_traced,
            simulate_close_failure: opts.simulate_close_failure,
            bound_generation: None,
            published: false,
            scratch_dir,
        })
    }

    /// Sets whether the supervisor's per-call grant/lease check succeeds.
    pub fn set_lease_active(&self, active: bool) {
        self.lease_active.store(active, Ordering::SeqCst);
    }

    /// Shared handle to the lease flag.
    #[must_use]
    pub fn lease_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.lease_active)
    }

    /// Returns whether this supervisor's session lease is currently active.
    #[must_use]
    pub fn is_lease_active(&self) -> bool {
        self.lease_active.load(Ordering::SeqCst)
    }

    /// Returns whether the recipient browser context has been published and
    /// the lease is active.
    #[must_use]
    pub fn is_published(&self) -> bool {
        self.published && self.is_lease_active()
    }

    /// Returns the bound attempt generation, if any.
    #[must_use]
    pub fn bound_generation(&self) -> Option<&str> {
        self.bound_generation.as_deref()
    }

    /// Enables or disables simulated tracer detection for testing `traced`
    /// refusal on `inject_state`.
    pub fn set_simulate_traced(&mut self, traced: bool) {
        self.simulate_traced = traced;
    }

    /// Enables or disables simulated close failure (`cleanup_failed`) on
    /// `close(generation)`.
    pub fn set_simulate_close_failure(&mut self, fail: bool) {
        self.simulate_close_failure = fail;
    }

    fn is_currently_traced(&self) -> bool {
        self.simulate_traced || !matches!(envcloak_sys::tracer_present(), Ok(false))
    }

    fn send_mcp_raw(&mut self, msg: &Value) -> Result<Value, SupervisorError> {
        let mut line = serde_json::to_string(msg)
            .map_err(|e| SupervisorError::Runtime(format!("serialize mcp: {e}")))?;
        if line.len() > MAX_SUPERVISOR_LINE_BYTES {
            return Err(SupervisorError::Runtime("mcp_request_too_large".to_owned()));
        }
        line.push('\n');
        self.mcp_in
            .write_all(line.as_bytes())
            .map_err(|e| SupervisorError::Runtime(format!("write helper stdin: {e}")))?;
        self.mcp_in
            .flush()
            .map_err(|e| SupervisorError::Runtime(format!("flush helper stdin: {e}")))?;

        let want_id = msg.get("id").cloned().unwrap_or(Value::Null);
        loop {
            let mut reply_line = String::new();
            let n = (&mut self.mcp_out)
                .take((MAX_SUPERVISOR_LINE_BYTES + 1) as u64)
                .read_line(&mut reply_line)
                .map_err(|e| SupervisorError::Runtime(format!("read helper stdout: {e}")))?;
            if n == 0 {
                return Err(SupervisorError::Runtime("helper_stdout_closed".to_owned()));
            }
            if reply_line.len() > MAX_SUPERVISOR_LINE_BYTES {
                return Err(SupervisorError::Runtime(
                    "mcp_response_too_large".to_owned(),
                ));
            }
            let trimmed = reply_line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parsed: Value = serde_json::from_str(trimmed)
                .map_err(|e| SupervisorError::Runtime(format!("invalid mcp json: {e}")))?;
            if parsed.get("id") == Some(&want_id) {
                return Ok(parsed);
            }
        }
    }

    /// Performs the MCP `initialize` handshake with the helper.
    pub fn mcp_initialize(&mut self) -> Result<Value, SupervisorError> {
        let id = self.next_id;
        self.next_id += 1;
        let init = self.send_mcp_raw(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "envcloak-supervisor", "version": "0.1.0" }
            }
        }))?;
        let notif =
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n";
        self.mcp_in.write_all(notif.as_bytes()).map_err(|e| {
            SupervisorError::Runtime(format!("write initialized notification: {e}"))
        })?;
        self.mcp_in.flush().map_err(|e| {
            SupervisorError::Runtime(format!("flush initialized notification: {e}"))
        })?;
        Ok(init)
    }

    /// Lists the raw, unfiltered tools reported by `@playwright/mcp`.
    pub fn raw_tools_list(&mut self) -> Result<Vec<Value>, SupervisorError> {
        let id = self.next_id;
        self.next_id += 1;
        let reply = self.send_mcp_raw(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": {}
        }))?;
        reply
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| SupervisorError::Runtime(format!("missing result.tools in {reply}")))
    }

    /// Lists tools from the helper and filters them through [`ToolAllowlist::list`].
    pub fn tools_list(&mut self) -> Result<Vec<Value>, SupervisorError> {
        let raw_tools = self.raw_tools_list()?;
        Ok(ToolAllowlist::list(&raw_tools))
    }

    /// Calls a browser tool through the supervisor.
    ///
    /// Enforces [`ToolAllowlist::admit`] and the per-call lease check before
    /// forwarding anything to the helper process.
    pub fn tools_call(&mut self, name: &str, arguments: Value) -> Result<Value, SupervisorError> {
        if let Err(code) = ToolAllowlist::admit(name, &arguments) {
            return Ok(json!({
                "isError": true,
                "refusedBySupervisor": true,
                "reason": code,
                "content": [{ "type": "text", "text": code }]
            }));
        }
        if !self.lease_active.load(Ordering::SeqCst) {
            return Ok(json!({
                "isError": true,
                "refusedBySupervisor": true,
                "reason": GRANT_REVOKED,
                "content": [{ "type": "text", "text": GRANT_REVOKED }]
            }));
        }
        let id = self.next_id;
        self.next_id += 1;
        let reply = self.send_mcp_raw(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }))?;
        if let Some(err) = reply.get("error") {
            return Ok(json!({
                "isError": true,
                "rpcError": err,
                "content": [{
                    "type": "text",
                    "text": err.get("message").and_then(Value::as_str).unwrap_or("rpc_error")
                }]
            }));
        }
        reply.get("result").cloned().ok_or_else(|| {
            SupervisorError::Runtime(format!("missing result in tools/call reply: {reply}"))
        })
    }

    fn send_control(&mut self, mut payload: Value) -> Result<Value, SupervisorError> {
        let id = self.next_id;
        self.next_id += 1;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("id".to_owned(), json!(id));
        }
        let mut line = Zeroizing::new(
            serde_json::to_string(&payload)
                .map_err(|e| SupervisorError::Runtime(format!("control json: {e}")))?,
        );
        if line.len() > MAX_SUPERVISOR_LINE_BYTES {
            return Err(SupervisorError::Runtime(
                "control_request_too_large".to_owned(),
            ));
        }
        line.push('\n');
        self.ctrl_write
            .write_all(line.as_bytes())
            .map_err(|e| SupervisorError::Runtime(format!("write control fd: {e}")))?;
        self.ctrl_write
            .flush()
            .map_err(|e| SupervisorError::Runtime(format!("flush control fd: {e}")))?;

        let mut reply_line = Zeroizing::new(String::new());
        let n = (&mut self.ctrl_read)
            .take((MAX_SUPERVISOR_LINE_BYTES + 1) as u64)
            .read_line(&mut reply_line)
            .map_err(|e| SupervisorError::Runtime(format!("read control fd: {e}")))?;
        if n == 0 {
            return Err(SupervisorError::Runtime(
                "control_channel_closed".to_owned(),
            ));
        }
        if reply_line.len() > MAX_SUPERVISOR_LINE_BYTES {
            return Err(SupervisorError::Runtime(
                "control_response_too_large".to_owned(),
            ));
        }
        let parsed: Value = serde_json::from_str(reply_line.trim())
            .map_err(|e| SupervisorError::Runtime(format!("invalid control reply json: {e}")))?;
        if parsed.get("ok").and_then(Value::as_bool) != Some(true) {
            let err_msg = parsed
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("control_command_failed")
                .to_owned();
            if err_msg.contains(UNSUPPORTED_SESSION_SCOPE) {
                return Err(SupervisorError::UnsupportedSessionScope(err_msg));
            }
            if err_msg.contains("generation_mismatch")
                || err_msg.contains("generation_already_bound")
                || err_msg.contains("missing_generation")
            {
                return Err(SupervisorError::GenerationMismatch(err_msg));
            }
            return Err(SupervisorError::Runtime(err_msg));
        }
        Ok(parsed.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Control command: `create_context(generation)`.
    pub fn create_context(&mut self, generation: &str) -> Result<Value, SupervisorError> {
        let res = self.send_control(json!({
            "cmd": "create_context",
            "generation": generation,
        }))?;
        self.bound_generation = Some(generation.to_owned());
        self.published = false;
        Ok(res)
    }

    /// Injects `DeclaredSecretState` into the private recipient context over
    /// the private control socketpair.
    ///
    /// Refuses with [`SupervisorError::Traced`] (`traced`) if the supervisor is
    /// under a tracer, and with [`SupervisorError::UnsupportedSessionScope`]
    /// (`unsupported_session_scope`) if any cookie/origin violates the declared
    /// scope or if Chromium/Playwright rewrites any cookie metadata on import
    /// (`cycle342` post-`addCookies` re-read).
    #[allow(clippy::disallowed_methods)] // Reviewed in security/expose-allowlist.txt: writes declared session cookie and localStorage values over the private control pipe to the pinned browser helper only.
    pub fn inject_secret_state(
        &mut self,
        generation: &str,
        state: &DeclaredSecretState,
    ) -> Result<Value, SupervisorError> {
        if self.is_currently_traced() {
            return Err(SupervisorError::Traced);
        }
        let cookies_json: Vec<Value> = state
            .cookies
            .iter()
            .map(|c| {
                let mut m = serde_json::Map::new();
                m.insert("name".to_owned(), json!(c.name));
                m.insert("value".to_owned(), json!(c.value.expose_secret()));
                m.insert("domain".to_owned(), json!(c.domain));
                m.insert("path".to_owned(), json!(c.path));
                m.insert("httpOnly".to_owned(), json!(c.http_only));
                m.insert("secure".to_owned(), json!(c.secure));
                if let Some(ss) = &c.same_site {
                    m.insert("sameSite".to_owned(), json!(ss));
                }
                if let Some(fmt) = &c.format {
                    m.insert("format".to_owned(), json!(fmt));
                }
                if c.device_bound {
                    m.insert("device_bound".to_owned(), json!(true));
                }
                Value::Object(m)
            })
            .collect();

        let origins_json: Vec<Value> = state
            .origins
            .iter()
            .map(|o| {
                let ls: Vec<Value> = o
                    .local_storage
                    .iter()
                    .map(|item| {
                        json!({
                            "name": item.name,
                            "value": item.value.expose_secret(),
                        })
                    })
                    .collect();
                json!({
                    "origin": o.origin,
                    "localStorage": ls,
                })
            })
            .collect();

        let declared = json!({
            "allowed_cookie_domains": state.allowed_cookie_domains,
            "allowed_origins": state.allowed_origins,
            "cookies": cookies_json,
            "origins": origins_json,
        });
        self.inject_state(generation, declared)
    }

    /// Control command: `inject_state(generation, declared_state)`.
    ///
    /// Refuses with [`SupervisorError::Traced`] (`traced`) when the supervisor
    /// is under a tracer.
    pub fn inject_state(
        &mut self,
        generation: &str,
        declared_state: Value,
    ) -> Result<Value, SupervisorError> {
        if self.is_currently_traced() {
            return Err(SupervisorError::Traced);
        }
        self.send_control(json!({
            "cmd": "inject_state",
            "generation": generation,
            "declared_state": declared_state,
        }))
    }

    /// Control command: `read_identity(generation, check) -> bounded response`.
    pub fn read_identity(
        &mut self,
        generation: &str,
        check: Value,
    ) -> Result<IdentityResponse, SupervisorError> {
        let res = self.send_control(json!({
            "cmd": "read_identity",
            "generation": generation,
            "check": check,
        }))?;
        let status = res
            .get("status")
            .and_then(Value::as_u64)
            .and_then(|s| u16::try_from(s).ok())
            .ok_or_else(|| {
                SupervisorError::Runtime(format!("invalid status in identity response: {res}"))
            })?;
        let body = res
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let truncated = res
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(IdentityResponse {
            status,
            body,
            truncated,
        })
    }

    /// Control command: `publish(generation)`.
    pub fn publish(&mut self, generation: &str) -> Result<Value, SupervisorError> {
        let res = self.send_control(json!({
            "cmd": "publish",
            "generation": generation,
        }))?;
        self.published = true;
        Ok(res)
    }

    /// Reads the bounded identity response from the private recipient context,
    /// matches `account`, `tenant`, and `role` in the supervisor/daemon role
    /// (D-31: the helper never reports a match), and calls `publish(generation)`
    /// only when the identity response matches `expected`.
    pub fn verify_and_publish(
        &mut self,
        generation: &str,
        check: Value,
        expected: &ExpectedIdentity,
    ) -> Result<IdentityResponse, SupervisorError> {
        let resp = self.read_identity(generation, check)?;
        if resp.truncated || resp.status != 200 {
            return Err(SupervisorError::IdentityUnverified(format!(
                "status={} truncated={}",
                resp.status, resp.truncated
            )));
        }
        let body_json: Value = serde_json::from_str(&resp.body)
            .map_err(|_| SupervisorError::IdentityUnverified("invalid_json".to_owned()))?;
        let account = body_json.get("account").and_then(Value::as_str);
        let tenant = body_json.get("tenant").and_then(Value::as_str);
        let role = body_json.get("role").and_then(Value::as_str);
        if account != Some(expected.account.as_str())
            || tenant != Some(expected.tenant.as_str())
            || role != Some(expected.role.as_str())
        {
            return Err(SupervisorError::IdentityUnverified(format!(
                "expected ({}, {}, {}), got ({account:?}, {tenant:?}, {role:?})",
                expected.account, expected.tenant, expected.role
            )));
        }
        self.publish(generation)?;
        Ok(resp)
    }

    /// Flips only the helper's `published` getter flag without closing the
    /// context (Observation 13).
    pub fn unpublish_getter_only(&mut self, generation: &str) -> Result<Value, SupervisorError> {
        let res = self.send_control(json!({
            "cmd": "unpublish_getter_only",
            "generation": generation,
        }))?;
        self.published = false;
        Ok(res)
    }

    /// Runs a worker login in an isolated worker context on the browser,
    /// captures the resulting cookies and storage, and closes the worker
    /// context without ever exposing it to `contextGetter`.
    pub fn worker_login_and_capture(
        &mut self,
        login_url: &str,
        username: &str,
        password: &str,
        totp: Option<&str>,
    ) -> Result<Value, SupervisorError> {
        self.send_control(json!({
            "cmd": "worker_login_and_capture",
            "login_url": login_url,
            "username": username,
            "password": password,
            "totp": totp,
        }))
    }

    /// Navigates a temporary worker `BrowserContext` to `url`, captures the
    /// resulting `workerContext.cookies()` snapshot, and closes the worker
    /// context (`cycle342` live cookie capture -> `inject_state` verification).
    pub fn capture_cookies_from_url(&mut self, url: &str) -> Result<Vec<Value>, SupervisorError> {
        let res = self.send_control(json!({
            "cmd": "capture_cookies_from_url",
            "url": url,
            "ignore_https_errors": true,
        }))?;
        Ok(res
            .get("cookies")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// Verifies that a second `BrowserContext` in the same browser stays
    /// usable after the recipient context is closed.
    pub fn verify_shared_browser_isolation(&mut self, url: &str) -> Result<Value, SupervisorError> {
        self.send_control(json!({
            "cmd": "verify_shared_browser_isolation",
            "url": url,
        }))
    }

    /// Control command: `close(generation)`.
    pub fn close(&mut self, generation: &str) -> Result<Value, SupervisorError> {
        self.published = false;
        self.set_lease_active(false);
        if self.simulate_close_failure {
            return Err(SupervisorError::Runtime("cleanup_failed".to_owned()));
        }
        self.send_control(json!({
            "cmd": "close",
            "generation": generation,
        }))
    }

    /// Injects a [`envcloak_ipc::control::SupervisorInjectState`] frame received
    /// from `envcloakd` over the supervisor control channel.
    #[allow(clippy::disallowed_methods)] // Reviewed in security/expose-allowlist.txt: writes declared session cookie and localStorage values over the private control pipe to the pinned browser helper only.
    pub fn inject_daemon_control_state(
        &mut self,
        msg: &envcloak_ipc::control::SupervisorInjectState,
    ) -> Result<Value, SupervisorError> {
        if self.is_currently_traced() {
            return Err(SupervisorError::Traced);
        }
        let gen_str = msg.generation.to_string();
        let cookies_json: Vec<Value> = msg
            .cookies
            .iter()
            .map(|c| {
                let val_str =
                    String::from_utf8_lossy(c.value.as_secret().expose_secret()).into_owned();
                let domain = if c.host_only {
                    c.domain.trim_start_matches('.').to_owned()
                } else if c.domain.starts_with('.') {
                    c.domain.clone()
                } else {
                    format!(".{}", c.domain)
                };
                json!({
                    "name": c.name,
                    "value": val_str,
                    "domain": domain,
                    "path": c.path,
                })
            })
            .collect();

        let mut origins_map: std::collections::BTreeMap<String, Vec<Value>> =
            std::collections::BTreeMap::new();
        for s in &msg.storage {
            let val_str = String::from_utf8_lossy(s.value.as_secret().expose_secret()).into_owned();
            origins_map
                .entry(s.origin.clone())
                .or_default()
                .push(json!({
                    "name": s.key,
                    "value": val_str,
                }));
        }
        let origins_json: Vec<Value> = origins_map
            .into_iter()
            .map(|(origin, ls)| {
                json!({
                    "origin": origin,
                    "localStorage": ls,
                })
            })
            .collect();

        self.send_control(json!({
            "cmd": "inject_state",
            "generation": gen_str,
            "declared_state": {
                "cookies": cookies_json,
                "origins": origins_json,
            }
        }))
    }

    /// Returns diagnostic statistics from the helper process.
    pub fn helper_stats(&mut self) -> Result<HelperStats, SupervisorError> {
        let res = self.send_control(json!({ "cmd": "get_stats" }))?;
        let pkg = res.get("package_surface").cloned().unwrap_or(Value::Null);
        let forwarded_calls = res
            .get("forwarded_calls")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("name").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        Ok(HelperStats {
            has_create_connection: pkg
                .get("has_create_connection")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            mcp_version: pkg
                .get("mcp_version")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            playwright_version: pkg
                .get("playwright_version")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            bound_generation: res
                .get("bound_generation")
                .and_then(Value::as_str)
                .map(str::to_owned),
            published: res
                .get("published")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            closed: res.get("closed").and_then(Value::as_bool).unwrap_or(false),
            getter_calls: res.get("getter_calls").and_then(Value::as_u64).unwrap_or(0),
            getter_refusals: res
                .get("getter_refusals")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            forwarded_calls,
        })
    }
}

impl Drop for BrowserSupervisor {
    fn drop(&mut self) {
        let _ = self.send_control(json!({ "cmd": "close", "generation": "" }));
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.scratch_dir);
    }
}

/// Entrypoint for `envcloak mcp --browser-supervisor` (SPEC §7.6, M2b-08).
///
/// Only `envcloakd` starts this internal mode. Invoking it directly from any
/// other process returns `not_started_by_daemon` (exit code 125) without
/// starting a browser helper or reading any session state.
pub fn run_browser_supervisor() -> Result<(), envcloak_client::fail::Failure> {
    use envcloak_client::fail::{Failure, refuse_if_traced};
    use envcloak_ipc::control::{
        FromSupervisor, SupervisorCheck, SupervisorIdentityResponse, ToSupervisor, receive, send,
    };

    refuse_if_traced()?;
    let daemon_control = if let Some(stream) = crate::bridge::handoff::started_by_daemon() {
        stream
    } else if let Ok(fd) = verify_started_by_daemon() {
        UnixStream::from(fd)
    } else {
        return Err(Failure::new(
            NOT_STARTED_BY_DAEMON,
            "this internal mode is started by envcloakd only; nothing was run",
        ));
    };

    let _ = daemon_control.set_read_timeout(Some(Duration::from_secs(30)));
    let first_msg: ToSupervisor = receive(&daemon_control).map_err(|_| {
        Failure::new(
            NOT_STARTED_BY_DAEMON,
            "the daemon control channel closed before delivering session state",
        )
    })?;
    let ToSupervisor::InjectState(inject) = first_msg else {
        return Err(Failure::new(
            NOT_STARTED_BY_DAEMON,
            "unexpected initial message on the supervisor control channel",
        ));
    };

    // Re-check tracer attachment immediately before accepting InjectState.
    refuse_if_traced()?;

    let mut sup = BrowserSupervisor::start(SupervisorOptions::default())
        .map_err(SupervisorError::into_cli_failure)?;
    let gen_str = inject.generation.to_string();
    sup.create_context(&gen_str)
        .map_err(SupervisorError::into_cli_failure)?;
    sup.inject_daemon_control_state(&inject)
        .map_err(SupervisorError::into_cli_failure)?;

    let id_resp = FromSupervisor::IdentityResponse(SupervisorIdentityResponse {
        request: inject.request.clone(),
        generation: inject.generation,
        context: inject.context.clone(),
        account: None,
        tenant: None,
        role: None,
    });
    send(&daemon_control, &id_resp)
        .map_err(|_| Failure::new("io", "failed to send identity response to daemon"))?;

    match receive::<ToSupervisor>(&daemon_control) {
        Ok(ToSupervisor::Publish(pub_msg)) if pub_msg.published => {
            sup.publish(&gen_str)
                .map_err(SupervisorError::into_cli_failure)?;
        }
        Ok(ToSupervisor::Publish(_) | ToSupervisor::Close(_)) => {
            let cleaned = sup.close(&gen_str).is_ok();
            let _ = send(
                &daemon_control,
                &FromSupervisor::Check(SupervisorCheck {
                    request: inject.request,
                    generation: inject.generation,
                    context: inject.context,
                    tool: None,
                    cleaned: Some(cleaned),
                }),
            );
            return Ok(());
        }
        Err(_) => {
            let _ = sup.close(&gen_str);
            return Err(Failure::new(
                "io",
                "daemon control channel closed before publication decision",
            ));
        }
        Ok(ToSupervisor::InjectState(_)) => {
            let _ = sup.close(&gen_str);
            return Err(Failure::new(
                "protocol_error",
                "duplicate InjectState on supervisor control channel",
            ));
        }
    }

    Ok(())
}
