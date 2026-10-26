//! Hosted browser helper supervisor prototype, tool allowlist (D-30, D-31),
//! Chrome for Testing pin verification and process measurements (D-29, D-34,
//! Q-06), and the sign-in fixture app harness (M2 plan task M2b-02).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;

use crate::agents::{cache_dir, platform, sha256_file};
use crate::home::DIAGNOSTIC_VARS;

/// Maximum JSON-RPC or control line size accepted by the supervisor prototype.
pub const MAX_SUPERVISOR_LINE_BYTES: usize = 1024 * 1024;

/// Fixed unavailable error thrown by the helper's context getter before
/// publication or after close.
pub const CONTEXT_NOT_PUBLISHED: &str = "sign_in_context_not_published";

/// Core page-interaction tools allowed by D-30 (`SPEC.md` §6.8).
pub const ALLOWED_BROWSER_TOOLS: &[&str] = &[
    "browser_close",
    "browser_resize",
    "browser_console_messages",
    "browser_handle_dialog",
    "browser_evaluate",
    "browser_fill_form",
    "browser_press_key",
    "browser_type",
    "browser_navigate",
    "browser_navigate_back",
    "browser_network_requests",
    "browser_take_screenshot",
    "browser_snapshot",
    "browser_click",
    "browser_drag",
    "browser_hover",
    "browser_select_option",
    "browser_tabs",
    "browser_wait_for",
];

/// Argument names stripped from tool input schemas and refused on `tools/call`
/// (`D-30`: no browser tool may write to or read from a caller-chosen local path).
pub const FORBIDDEN_PATH_ARGS: &[&str] = &[
    "filename",
    "outputPath",
    "output_path",
    "path",
    "paths",
    "savePath",
    "save_path",
];

/// D-30 hosted browser tool allowlist and argument filter.
#[derive(Debug, Clone, Default)]
pub struct ToolAllowlist;

impl ToolAllowlist {
    /// Filters `tools/list` entries to [`ALLOWED_BROWSER_TOOLS`] and strips
    /// [`FORBIDDEN_PATH_ARGS`] from every tool's `inputSchema`.
    pub fn list(raw_tools: &[Value]) -> Vec<Value> {
        let mut out = Vec::new();
        for tool in raw_tools {
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            if !ALLOWED_BROWSER_TOOLS.contains(&name) {
                continue;
            }
            let mut cleaned = tool.clone();
            if let Some(schema) = cleaned
                .get_mut("inputSchema")
                .and_then(Value::as_object_mut)
            {
                if let Some(props) = schema.get_mut("properties").and_then(Value::as_object_mut) {
                    for forbidden in FORBIDDEN_PATH_ARGS {
                        props.remove(*forbidden);
                    }
                }
                if let Some(req) = schema.get_mut("required").and_then(Value::as_array_mut) {
                    req.retain(|v| v.as_str().is_none_or(|s| !FORBIDDEN_PATH_ARGS.contains(&s)));
                }
            }
            out.push(cleaned);
        }
        out
    }

    /// Checks whether a `tools/call` for `name` with `args` is permitted by
    /// D-30 before forwarding to the helper process.
    ///
    /// # Errors
    /// Returns `"tool_not_allowed"` when `name` is not in
    /// [`ALLOWED_BROWSER_TOOLS`], when `args` carries a `filename` or
    /// output-path argument, or when a navigation URL uses a scheme other than
    /// `http:` or `https:`.
    pub fn admit(name: &str, args: &Value) -> Result<(), &'static str> {
        if !ALLOWED_BROWSER_TOOLS.contains(&name) {
            return Err("tool_not_allowed");
        }
        let map = match args {
            Value::Null => None,
            Value::Object(m) => Some(m),
            _ => return Err("tool_not_allowed"),
        };
        if let Some(m) = map {
            for key in m.keys() {
                if FORBIDDEN_PATH_ARGS.contains(&key.as_str()) {
                    return Err("tool_not_allowed");
                }
            }
            if name == "browser_navigate" {
                let Some(url) = m.get("url").and_then(Value::as_str) else {
                    return Err("tool_not_allowed");
                };
                if !is_allowed_http_url(url) {
                    return Err("tool_not_allowed");
                }
            } else if name == "browser_tabs" {
                if let Some(url_val) = m.get("url") {
                    let Some(url) = url_val.as_str() else {
                        return Err("tool_not_allowed");
                    };
                    if !is_allowed_http_url(url) {
                        return Err("tool_not_allowed");
                    }
                }
            }
        } else if name == "browser_navigate" {
            return Err("tool_not_allowed");
        }
        Ok(())
    }
}

fn is_allowed_http_url(url: &str) -> bool {
    let trimmed = url.trim();
    let rest = if let Some(r) = trimmed
        .get(..7)
        .and_then(|p| p.eq_ignore_ascii_case("http://").then(|| &trimmed[7..]))
    {
        r
    } else if let Some(r) = trimmed
        .get(..8)
        .and_then(|p| p.eq_ignore_ascii_case("https://").then(|| &trimmed[8..]))
    {
        r
    } else {
        return false;
    };
    !rest.is_empty() && !rest.starts_with('/')
}

/// Repository root relative to `envcloak-testkit`'s manifest directory.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("envcloak-testkit is not under <root>/crates/"))
        .to_path_buf()
}

/// Default path to `integrations/browser/versions.toml`.
pub fn browser_versions_path() -> PathBuf {
    repo_root().join("integrations/browser/versions.toml")
}

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

/// Reads [`BrowserPins`] for the current platform from `versions_toml`.
///
/// # Errors
/// Returns a description when the file cannot be parsed or lacks a required pin.
pub fn read_browser_pins(versions_toml: &Path) -> Result<BrowserPins, String> {
    let plat = platform().ok_or_else(|| "unsupported platform for browser pins".to_owned())?;
    let text = std::fs::read_to_string(versions_toml)
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

/// Verifies a Chrome for Testing executable against `expected_sha256` and
/// checks that `com.apple.quarantine` is absent on macOS.
///
/// # Errors
/// Returns an error when the file is missing, its SHA-256 does not match
/// `expected_sha256`, or it carries `com.apple.quarantine`.
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

/// Environment variable set in CI browser jobs so a missing or mismatched
/// browser runtime fails the test instead of skipping.
pub const REQUIRE_BROWSER_RUNTIME_VAR: &str = "ENVCLOAK_REQUIRE_BROWSER_RUNTIME";

/// Command to provision and verify the pinned browser runtime.
pub const INSTALL_BROWSER_RUNTIME: &str = "python3 scripts/install-browser-runtime.py";

/// Resolves and verifies the pinned Node.js binary against `pins`.
///
/// Checks `ENVCLOAK_NODE_BIN` first, then `<cache_dir>/node-<version>-<plat>/bin/node`,
/// and verifies its SHA-256 against `pins.node_sha256`.
///
/// # Errors
/// Returns an error if the binary is missing or its SHA-256 does not match `pins.node_sha256`.
pub fn resolve_node_binary(pins: &BrowserPins) -> Result<PathBuf, String> {
    let plat = platform().ok_or_else(|| "unsupported platform".to_owned())?;
    let node_exe = if let Some(env_node) = std::env::var_os("ENVCLOAK_NODE_BIN") {
        PathBuf::from(env_node)
    } else {
        cache_dir()
            .join(format!("node-{}-{plat}", pins.node_version))
            .join("bin/node")
    };
    let got_node = sha256_file(&node_exe)
        .map_err(|e| format!("pinned Node missing at {}: {e}", node_exe.display()))?;
    if got_node != pins.node_sha256 {
        return Err(format!(
            "node_hash_mismatch: {} has SHA-256 {got_node}, expected {}",
            node_exe.display(),
            pins.node_sha256
        ));
    }
    Ok(node_exe)
}

/// Finds and verifies the pinned Node runtime, `@playwright/mcp` helper
/// modules, and Chrome for Testing executable against `versions_toml`.
///
/// # Errors
/// Returns why any component is missing or fails its SHA-256 / version pin.
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
    if let Some(env_dir) = std::env::var_os("ENVCLOAK_BROWSER_HELPER_NODE_MODULES") {
        module_candidates.push(PathBuf::from(env_dir));
    }
    if let Some(env_dir) = std::env::var_os("ENVCLOAK_BROWSER_HELPER_MODULES") {
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
        let mcp_ver = std::fs::read(&mcp_pkg_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v.get("version").and_then(Value::as_str).map(str::to_owned));
        let pw_ver = std::fs::read(&pw_pkg_path)
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
    if let Some(env_chrome) = std::env::var_os("ENVCLOAK_CHROME_FOR_TESTING_BIN") {
        chrome_candidates.push(PathBuf::from(env_chrome));
    }
    if let Some(env_chrome) = std::env::var_os("ENVCLOAK_CHROME_FOR_TESTING") {
        chrome_candidates.push(PathBuf::from(env_chrome));
    }
    if let Some(pw_path) = std::env::var_os("PLAYWRIGHT_BROWSERS_PATH") {
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
    if let Some(home) = std::env::var_os("HOME") {
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

/// Resolves and verifies the pinned browser runtime for tests (`agents::require`
/// pattern).
///
/// When the runtime is not installed in the cache, skips the test with a notice
/// on stderr unless `ENVCLOAK_REQUIRE_BROWSER_RUNTIME` or
/// `ENVCLOAK_TEST_REQUIRE_AGENT_HOSTS` is set, in which case it panics.
///
/// # Panics
/// Panics if `ENVCLOAK_REQUIRE_BROWSER_RUNTIME` or
/// `ENVCLOAK_TEST_REQUIRE_AGENT_HOSTS` is set and the runtime is missing or
/// fails verification.
pub fn require_browser_runtime() -> Option<VerifiedBrowserRuntime> {
    match resolve_browser_runtime(&browser_versions_path()) {
        Ok(rt) => Some(rt),
        Err(why) => {
            if std::env::var_os(REQUIRE_BROWSER_RUNTIME_VAR).is_some()
                || std::env::var_os(crate::agents::REQUIRE_VAR).is_some()
            {
                panic!("browser runtime required ({why}; run: {INSTALL_BROWSER_RUNTIME})");
            }
            eprintln!("skipping browser runtime test ({why}; run: {INSTALL_BROWSER_RUNTIME})");
            None
        }
    }
}

/// Bounded response returned by the helper's `read_identity` control command.
/// Note (D-31): the helper never reports a match; the supervisor/daemon matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityResponse {
    pub status: u16,
    pub body: String,
    pub truncated: bool,
}

/// Expected identity fields matched by the daemon against [`IdentityResponse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedIdentity {
    pub account: String,
    pub tenant: String,
    pub role: String,
}

/// Diagnostic counters reported by the helper over the control channel.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Options for starting a [`BrowserSupervisor`].
#[derive(Debug, Clone, Default)]
pub struct SupervisorOptions {
    pub host_resolver_rules: Option<String>,
    pub isolated_control: bool,
}

/// Prototype Rust browser supervisor (moved into `envcloak-mcp` in M2b-08).
///
/// Spawns one `integrations/browser-helper` process per generation with a
/// cleared environment and pinned Node binary, bounds messages, filters
/// `tools/list` and `tools/call` through [`ToolAllowlist`], and checks the
/// grant/lease before forwarding every allowed tool call.
#[derive(Debug)]
pub struct BrowserSupervisor {
    child: Child,
    mcp_in: ChildStdin,
    mcp_out: BufReader<ChildStdout>,
    ctrl_write: UnixStream,
    ctrl_read: BufReader<UnixStream>,
    next_id: u64,
    lease_active: Arc<AtomicBool>,
    _temp_dir: TempDir,
}

impl BrowserSupervisor {
    /// Starts a supervisor and helper process using the default
    /// `integrations/browser/versions.toml`.
    ///
    /// # Errors
    /// Returns an error if any pin check fails or the helper cannot be spawned.
    pub fn start(opts: SupervisorOptions) -> Result<Self, String> {
        Self::start_with_versions(&browser_versions_path(), opts)
    }

    /// Starts a supervisor after verifying pins in `versions_toml`.
    ///
    /// # Errors
    /// Refuses to launch when Chrome for Testing, Node, or the helper fails
    /// its SHA-256 pin check.
    pub fn start_with_versions(
        versions_toml: &Path,
        opts: SupervisorOptions,
    ) -> Result<Self, String> {
        let runtime = resolve_browser_runtime(versions_toml)?;
        Self::start_with_runtime(&runtime, opts)
    }

    /// Starts a supervisor using an already-verified [`VerifiedBrowserRuntime`].
    ///
    /// # Errors
    /// Returns an error if pipes or process spawning fail.
    pub fn start_with_runtime(
        runtime: &VerifiedBrowserRuntime,
        opts: SupervisorOptions,
    ) -> Result<Self, String> {
        verify_chrome_executable(&runtime.chrome_exe, &runtime.pins.chrome_sha256)?;

        let temp_dir = tempfile::Builder::new()
            .prefix("ec-bhelper-")
            .tempdir()
            .map_err(|e| format!("tempdir: {e}"))?;
        let home_dir = temp_dir.path().join("home");
        let tmp_dir = temp_dir.path().join("tmp");
        let out_dir = temp_dir.path().join("out");
        std::fs::create_dir_all(&home_dir).map_err(|e| format!("mkdir home: {e}"))?;
        std::fs::create_dir_all(&tmp_dir).map_err(|e| format!("mkdir tmp: {e}"))?;
        std::fs::create_dir_all(&out_dir).map_err(|e| format!("mkdir out: {e}"))?;

        let (ctrl_parent, ctrl_child) =
            UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
        ctrl_parent
            .set_read_timeout(Some(Duration::from_secs(20)))
            .map_err(|e| format!("set_read_timeout: {e}"))?;
        ctrl_parent
            .set_write_timeout(Some(Duration::from_secs(20)))
            .map_err(|e| format!("set_write_timeout: {e}"))?;
        let ctrl_parent_read = ctrl_parent
            .try_clone()
            .map_err(|e| format!("clone control socket: {e}"))?;

        let child_fd_num = ctrl_child.as_raw_fd();
        let mut cmd = Command::new(&runtime.node_exe);
        cmd.env_clear();
        cmd.env("HOME", &home_dir);
        cmd.env("TMPDIR", &tmp_dir);
        cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        for var in DIAGNOSTIC_VARS {
            if let Some(val) = std::env::var_os(var) {
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
            .map_err(|e| format!("inherit_on_spawn: {e}"))?;

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("spawn browser-helper: {e}"))?;
        drop(cmd);
        drop(ctrl_child);

        let mcp_in = child.stdin.take().ok_or("missing helper stdin")?;
        let mcp_out = BufReader::new(child.stdout.take().ok_or("missing helper stdout")?);

        Ok(Self {
            child,
            mcp_in,
            mcp_out,
            ctrl_write: ctrl_parent,
            ctrl_read: BufReader::new(ctrl_parent_read),
            next_id: 1,
            lease_active: Arc::new(AtomicBool::new(true)),
            _temp_dir: temp_dir,
        })
    }

    /// Sets whether the supervisor's per-call grant/lease check succeeds.
    pub fn set_lease_active(&self, active: bool) {
        self.lease_active.store(active, Ordering::SeqCst);
    }

    /// Shared handle to the lease flag.
    pub fn lease_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.lease_active)
    }

    fn send_mcp_raw(&mut self, msg: &Value) -> Result<Value, String> {
        let mut line = serde_json::to_string(msg).map_err(|e| format!("serialize mcp: {e}"))?;
        if line.len() > MAX_SUPERVISOR_LINE_BYTES {
            return Err("mcp_request_too_large".to_owned());
        }
        line.push('\n');
        self.mcp_in
            .write_all(line.as_bytes())
            .map_err(|e| format!("write helper stdin: {e}"))?;
        self.mcp_in
            .flush()
            .map_err(|e| format!("flush helper stdin: {e}"))?;

        let want_id = msg.get("id").cloned().unwrap_or(Value::Null);
        loop {
            let mut reply_line = String::new();
            let n = (&mut self.mcp_out)
                .take((MAX_SUPERVISOR_LINE_BYTES + 1) as u64)
                .read_line(&mut reply_line)
                .map_err(|e| format!("read helper stdout: {e}"))?;
            if n == 0 {
                return Err("helper_stdout_closed".to_owned());
            }
            if reply_line.len() > MAX_SUPERVISOR_LINE_BYTES {
                return Err("mcp_response_too_large".to_owned());
            }
            let trimmed = reply_line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parsed: Value =
                serde_json::from_str(trimmed).map_err(|e| format!("invalid mcp json: {e}"))?;
            if parsed.get("id") == Some(&want_id) {
                return Ok(parsed);
            }
        }
    }

    /// Performs the MCP `initialize` handshake with the helper.
    pub fn mcp_initialize(&mut self) -> Result<Value, String> {
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
        self.mcp_in
            .write_all(notif.as_bytes())
            .map_err(|e| format!("write initialized notification: {e}"))?;
        self.mcp_in
            .flush()
            .map_err(|e| format!("flush initialized notification: {e}"))?;
        Ok(init)
    }

    /// Lists the raw, unfiltered tools reported by `@playwright/mcp`.
    pub fn raw_tools_list(&mut self) -> Result<Vec<Value>, String> {
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
            .ok_or_else(|| format!("missing result.tools in {reply}"))
    }

    /// Lists tools from the helper and filters them through [`ToolAllowlist::list`].
    pub fn tools_list(&mut self) -> Result<Vec<Value>, String> {
        let raw_tools = self.raw_tools_list()?;
        Ok(ToolAllowlist::list(&raw_tools))
    }

    /// Calls a browser tool through the supervisor.
    ///
    /// Enforces [`ToolAllowlist::admit`] and the per-call lease check before
    /// forwarding anything to the helper process.
    pub fn tools_call(&mut self, name: &str, arguments: Value) -> Result<Value, String> {
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
                "reason": "grant_revoked",
                "content": [{ "type": "text", "text": "grant_revoked" }]
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
        reply
            .get("result")
            .cloned()
            .ok_or_else(|| format!("missing result in tools/call reply: {reply}"))
    }

    fn send_control(&mut self, mut payload: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("id".to_owned(), json!(id));
        }
        let mut line = serde_json::to_string(&payload).map_err(|e| format!("control json: {e}"))?;
        if line.len() > MAX_SUPERVISOR_LINE_BYTES {
            return Err("control_request_too_large".to_owned());
        }
        line.push('\n');
        self.ctrl_write
            .write_all(line.as_bytes())
            .map_err(|e| format!("write control fd: {e}"))?;
        self.ctrl_write
            .flush()
            .map_err(|e| format!("flush control fd: {e}"))?;

        let mut reply_line = String::new();
        let n = (&mut self.ctrl_read)
            .take((MAX_SUPERVISOR_LINE_BYTES + 1) as u64)
            .read_line(&mut reply_line)
            .map_err(|e| format!("read control fd: {e}"))?;
        if n == 0 {
            return Err("control_channel_closed".to_owned());
        }
        if reply_line.len() > MAX_SUPERVISOR_LINE_BYTES {
            return Err("control_response_too_large".to_owned());
        }
        let parsed: Value = serde_json::from_str(reply_line.trim())
            .map_err(|e| format!("invalid control reply json: {e}"))?;
        if parsed.get("ok").and_then(Value::as_bool) != Some(true) {
            let err_msg = parsed
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("control_command_failed");
            return Err(err_msg.to_owned());
        }
        Ok(parsed.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Control command: `create_context(generation)`.
    pub fn create_context(&mut self, generation: &str) -> Result<Value, String> {
        self.send_control(json!({
            "cmd": "create_context",
            "generation": generation,
        }))
    }

    /// Control command: `inject_state(generation, declared_state)`.
    pub fn inject_state(
        &mut self,
        generation: &str,
        declared_state: Value,
    ) -> Result<Value, String> {
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
    ) -> Result<IdentityResponse, String> {
        let res = self.send_control(json!({
            "cmd": "read_identity",
            "generation": generation,
            "check": check,
        }))?;
        let status = res
            .get("status")
            .and_then(Value::as_u64)
            .and_then(|s| u16::try_from(s).ok())
            .ok_or_else(|| format!("invalid status in identity response: {res}"))?;
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
    pub fn publish(&mut self, generation: &str) -> Result<Value, String> {
        self.send_control(json!({
            "cmd": "publish",
            "generation": generation,
        }))
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
    ) -> Result<IdentityResponse, String> {
        let resp = self.read_identity(generation, check)?;
        if resp.truncated || resp.status != 200 {
            return Err("identity_unverified".to_owned());
        }
        let body_json: Value =
            serde_json::from_str(&resp.body).map_err(|_| "identity_unverified".to_owned())?;
        let account = body_json.get("account").and_then(Value::as_str);
        let tenant = body_json.get("tenant").and_then(Value::as_str);
        let role = body_json.get("role").and_then(Value::as_str);
        if account != Some(expected.account.as_str())
            || tenant != Some(expected.tenant.as_str())
            || role != Some(expected.role.as_str())
        {
            return Err("identity_unverified".to_owned());
        }
        self.publish(generation)?;
        Ok(resp)
    }

    /// Test-only control command: flips only the helper's `published` getter
    /// flag without closing the context, demonstrating Observation 13 (that
    /// `@playwright/mcp` caches an opened context so the supervisor's per-call
    /// lease check is required).
    pub fn unpublish_getter_only(&mut self, generation: &str) -> Result<Value, String> {
        self.send_control(json!({
            "cmd": "unpublish_getter_only",
            "generation": generation,
        }))
    }

    /// Control command: runs a worker login in an isolated worker context on
    /// the browser, captures the resulting cookies and storage, and closes the
    /// worker context without ever exposing it to `contextGetter`.
    pub fn worker_login_and_capture(
        &mut self,
        login_url: &str,
        username: &str,
        password: &str,
        totp: Option<&str>,
    ) -> Result<Value, String> {
        self.send_control(json!({
            "cmd": "worker_login_and_capture",
            "login_url": login_url,
            "username": username,
            "password": password,
            "totp": totp,
        }))
    }

    /// Control command: verifies that a second `BrowserContext` in the same
    /// browser stays usable after the recipient context is closed.
    pub fn verify_shared_browser_isolation(&mut self, url: &str) -> Result<Value, String> {
        self.send_control(json!({
            "cmd": "verify_shared_browser_isolation",
            "url": url,
        }))
    }

    /// Control command: `close(generation)`.
    pub fn close(&mut self, generation: &str) -> Result<Value, String> {
        self.send_control(json!({
            "cmd": "close",
            "generation": generation,
        }))
    }

    /// Returns diagnostic statistics from the helper process.
    pub fn helper_stats(&mut self) -> Result<HelperStats, String> {
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
    }
}

/// Origins and generated per-run credentials of a running [`SigninFixture`].
#[derive(Debug, Clone)]
pub struct Origins {
    pub app: String,
    pub idp: String,
    pub observer: String,
    pub unregistered: String,
    pub idn_lookalike: String,
    pub userinfo: String,
    pub changed_port: String,
    pub https_test_ca: String,
    pub https_self_signed: String,
    pub control: String,
    pub test_ca_cert_pem: String,
    pub build_number: String,
    pub editor_password: String,
    pub admin_password: String,
    pub editor_totp_secret_hex: String,
    pub admin_totp_secret_hex: String,
    pub adapter_key: String,
    pub host_resolver_rules: String,
}

/// Per-origin counters tracked by the sign-in fixture app.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OriginCounters {
    pub requests: u64,
    pub password_submissions: u64,
    pub code_submissions: u64,
    pub mints: u64,
    pub revocations: u64,
    pub exfiltrations: u64,
}

/// Aggregate and per-origin submission counters from [`Control::counters`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FixtureCounters {
    pub password_submissions: u64,
    pub code_submissions: u64,
    pub wrong_target_submissions: u64,
    pub mints: u64,
    pub revocations: u64,
    pub observer_cookie_hits: u64,
    pub exfiltration_by_channel: BTreeMap<String, u64>,
    pub by_origin: BTreeMap<String, OriginCounters>,
}

/// One accepted TOTP code logged by the sign-in fixture app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedCode {
    pub account: String,
    pub code: String,
    pub digits: u8,
    pub algorithm: String,
    pub step: u64,
    pub timestamp: u64,
}

/// Result of verifying a TOTP code against the fixture's independent Node
/// `crypto.createHmac` implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpVerdict {
    pub valid: bool,
    pub expected: Option<String>,
    pub step: Option<u64>,
    pub digits: u8,
    pub algorithm: String,
}

/// Control handle for a running [`SigninFixture`].
#[derive(Debug)]
pub struct Control {
    control_origin: String,
    child: Child,
    _stdin_hold: ChildStdin,
    _temp_dir: TempDir,
}

/// The sign-in fixture app (`crates/envcloak-e2e/fixtures/signin/server.cjs`).
#[derive(Debug)]
pub struct SigninFixture;

impl SigninFixture {
    /// Starts the sign-in fixture app under the pinned Node runtime and returns
    /// its bound [`Origins`] and [`Control`] handle.
    ///
    /// # Panics
    /// Panics if the pinned Node runtime is unavailable or the fixture fails
    /// to start.
    pub fn start() -> (Origins, Control) {
        Self::try_start().unwrap_or_else(|e| panic!("SigninFixture::start failed: {e}"))
    }

    /// Fallible version of [`SigninFixture::start`].
    ///
    /// # Errors
    /// Returns an error if the pinned Node binary cannot be verified or the
    /// fixture process fails to report its listening ports.
    pub fn try_start() -> Result<(Origins, Control), String> {
        let pins = read_browser_pins(&browser_versions_path())?;
        let node_exe = resolve_node_binary(&pins)?;

        let script = repo_root().join("crates/envcloak-e2e/fixtures/signin/server.cjs");
        if !script.is_file() {
            return Err(format!("missing fixture script {}", script.display()));
        }

        let temp_dir = tempfile::Builder::new()
            .prefix("ec-signin-fix-")
            .tempdir()
            .map_err(|e| format!("tempdir: {e}"))?;

        let mut cmd = Command::new(&node_exe);
        cmd.env_clear();
        cmd.env("HOME", temp_dir.path());
        cmd.env("TMPDIR", temp_dir.path());
        cmd.env("PATH", "/usr/bin:/bin");
        cmd.arg(&script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("spawn signin fixture: {e}"))?;
        let stdin_hold = child.stdin.take().ok_or("missing fixture stdin")?;
        let stdout = child.stdout.take().ok_or("missing fixture stdout")?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read fixture startup line: {e}"))?;
        if line.trim().is_empty() {
            return Err("signin fixture exited without printing startup JSON".to_owned());
        }
        let info: Value = serde_json::from_str(line.trim())
            .map_err(|e| format!("parse fixture startup JSON: {e}"))?;

        let str_field = |k: &str| -> Result<String, String> {
            info.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("missing field {k} in fixture startup JSON"))
        };

        let origins = Origins {
            app: str_field("app")?,
            idp: str_field("idp")?,
            observer: str_field("observer")?,
            unregistered: str_field("unregistered")?,
            idn_lookalike: str_field("idn_lookalike")?,
            userinfo: str_field("userinfo")?,
            changed_port: str_field("changed_port")?,
            https_test_ca: str_field("https_test_ca")?,
            https_self_signed: str_field("https_self_signed")?,
            control: str_field("control")?,
            test_ca_cert_pem: str_field("test_ca_cert_pem")?,
            build_number: str_field("build_number")?,
            editor_password: str_field("editor_password")?,
            admin_password: str_field("admin_password")?,
            editor_totp_secret_hex: str_field("editor_totp_secret_hex")?,
            admin_totp_secret_hex: str_field("admin_totp_secret_hex")?,
            adapter_key: str_field("adapter_key")?,
            host_resolver_rules: str_field("host_resolver_rules")?,
        };
        let control = Control {
            control_origin: origins.control.clone(),
            child,
            _stdin_hold: stdin_hold,
            _temp_dir: temp_dir,
        };
        Ok((origins, control))
    }
}

impl Control {
    /// Reads all current submission, mint, revocation, and exfiltration counters.
    pub fn counters(&self) -> Result<FixtureCounters, String> {
        let (_, body) = http_request(
            "GET",
            &format!("{}/control/counters", self.control_origin),
            &[],
            "",
        )?;
        let v: Value = serde_json::from_str(&body).map_err(|e| format!("counters json: {e}"))?;
        parse_counters(&v)
    }

    /// Reads the log of every accepted TOTP code.
    pub fn accepted_codes(&self) -> Result<Vec<AcceptedCode>, String> {
        let (_, body) = http_request(
            "GET",
            &format!("{}/control/accepted-codes", self.control_origin),
            &[],
            "",
        )?;
        let v: Value =
            serde_json::from_str(&body).map_err(|e| format!("accepted_codes json: {e}"))?;
        let arr = v
            .get("accepted_codes")
            .and_then(Value::as_array)
            .ok_or("missing accepted_codes array")?;
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            out.push(AcceptedCode {
                account: item
                    .get("account")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                code: item
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                digits: u8::try_from(item.get("digits").and_then(Value::as_u64).unwrap_or(8))
                    .unwrap_or(8),
                algorithm: item
                    .get("algorithm")
                    .and_then(Value::as_str)
                    .unwrap_or("SHA1")
                    .to_owned(),
                step: item.get("step").and_then(Value::as_u64).unwrap_or(0),
                timestamp: item.get("timestamp").and_then(Value::as_u64).unwrap_or(0),
            });
        }
        Ok(out)
    }

    /// Arms a named deterministic barrier on the fixture server so subsequent
    /// requests hitting `name` pause until [`Control::release`].
    pub fn barrier(&self, name: &str) -> Result<(), String> {
        let payload = json!({ "name": name, "action": "arm" }).to_string();
        let (status, body) = http_request(
            "POST",
            &format!("{}/control/barrier", self.control_origin),
            &[("content-type", "application/json")],
            &payload,
        )?;
        if status != 200 {
            return Err(format!("barrier({name}) failed: {status} {body}"));
        }
        Ok(())
    }

    /// Waits deterministically until at least one request is parked at barrier `name`.
    pub fn wait_barrier(&self, name: &str) -> Result<(), String> {
        let payload = json!({ "name": name, "action": "wait" }).to_string();
        let (status, body) = http_request(
            "POST",
            &format!("{}/control/barrier", self.control_origin),
            &[("content-type", "application/json")],
            &payload,
        )?;
        if status != 200 {
            return Err(format!("wait_barrier({name}) failed: {status} {body}"));
        }
        Ok(())
    }

    /// Releases a named barrier on the fixture server, waking all parked requests.
    pub fn release(&self, name: &str) -> Result<u64, String> {
        let payload = json!({ "name": name }).to_string();
        let (status, body) = http_request(
            "POST",
            &format!("{}/control/release", self.control_origin),
            &[("content-type", "application/json")],
            &payload,
        )?;
        if status != 200 {
            return Err(format!("release({name}) failed: {status} {body}"));
        }
        let v: Value = serde_json::from_str(&body).map_err(|e| format!("release json: {e}"))?;
        Ok(v.get("released").and_then(Value::as_u64).unwrap_or(0))
    }

    /// Resets all fixture counters and accepted codes.
    pub fn reset_counters(&self) -> Result<(), String> {
        let (status, body) = http_request(
            "POST",
            &format!("{}/control/reset", self.control_origin),
            &[("content-type", "application/json")],
            "{}",
        )?;
        if status != 200 {
            return Err(format!("reset_counters failed: {status} {body}"));
        }
        Ok(())
    }

    /// Expires all currently minted sessions on the server side (gate `b19`).
    pub fn expire_sessions(&self) -> Result<(), String> {
        let (status, body) = http_request(
            "POST",
            &format!("{}/control/expire-sessions", self.control_origin),
            &[("content-type", "application/json")],
            "{}",
        )?;
        if status != 200 {
            return Err(format!("expire_sessions failed: {status} {body}"));
        }
        Ok(())
    }

    /// Verifies a TOTP code using the fixture's independent Node
    /// `crypto.createHmac` implementation.
    pub fn verify_totp(
        &self,
        secret_hex: &str,
        timestamp_secs: u64,
        digits: u8,
        algorithm: &str,
        code: &str,
    ) -> Result<TotpVerdict, String> {
        let payload = json!({
            "secret_hex": secret_hex,
            "timestamp_secs": timestamp_secs,
            "digits": digits,
            "algorithm": algorithm,
            "code": code,
        })
        .to_string();
        let (status, body) = http_request(
            "POST",
            &format!("{}/control/totp-verify", self.control_origin),
            &[("content-type", "application/json")],
            &payload,
        )?;
        if status != 200 {
            return Err(format!("verify_totp failed: {status} {body}"));
        }
        let v: Value = serde_json::from_str(&body).map_err(|e| format!("totp json: {e}"))?;
        Ok(TotpVerdict {
            valid: v.get("valid").and_then(Value::as_bool).unwrap_or(false),
            expected: v.get("expected").and_then(Value::as_str).map(str::to_owned),
            step: v.get("step").and_then(Value::as_u64),
            digits: u8::try_from(v.get("digits").and_then(Value::as_u64).unwrap_or(8)).unwrap_or(8),
            algorithm: v
                .get("algorithm")
                .and_then(Value::as_str)
                .unwrap_or("SHA1")
                .to_owned(),
        })
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Parses a [`FixtureCounters`] JSON payload. Exposed so self-tests can verify
/// exact counter decoding.
pub fn parse_counters(v: &Value) -> Result<FixtureCounters, String> {
    let mut exfil = BTreeMap::new();
    if let Some(obj) = v.get("exfiltration_by_channel").and_then(Value::as_object) {
        for (k, val) in obj {
            exfil.insert(k.clone(), val.as_u64().unwrap_or(0));
        }
    }
    let mut by_origin = BTreeMap::new();
    if let Some(obj) = v.get("by_origin").and_then(Value::as_object) {
        for (k, val) in obj {
            by_origin.insert(
                k.clone(),
                OriginCounters {
                    requests: val.get("requests").and_then(Value::as_u64).unwrap_or(0),
                    password_submissions: val
                        .get("password_submissions")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    code_submissions: val
                        .get("code_submissions")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    mints: val.get("mints").and_then(Value::as_u64).unwrap_or(0),
                    revocations: val.get("revocations").and_then(Value::as_u64).unwrap_or(0),
                    exfiltrations: val
                        .get("exfiltrations")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                },
            );
        }
    }
    Ok(FixtureCounters {
        password_submissions: v
            .get("password_submissions")
            .and_then(Value::as_u64)
            .ok_or("missing password_submissions")?,
        code_submissions: v
            .get("code_submissions")
            .and_then(Value::as_u64)
            .ok_or("missing code_submissions")?,
        wrong_target_submissions: v
            .get("wrong_target_submissions")
            .and_then(Value::as_u64)
            .ok_or("missing wrong_target_submissions")?,
        mints: v
            .get("mints")
            .and_then(Value::as_u64)
            .ok_or("missing mints")?,
        revocations: v
            .get("revocations")
            .and_then(Value::as_u64)
            .ok_or("missing revocations")?,
        observer_cookie_hits: v
            .get("observer_cookie_hits")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        exfiltration_by_channel: exfil,
        by_origin,
    })
}

/// Sends an HTTP/1.1 request to a local fixture origin (resolving `.localhost`
/// hostnames directly to `127.0.0.1`) and returns `(status_code, body)`.
pub fn http_request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<(u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("expected http:// url, got {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let host_port = match authority.rfind('@') {
        Some(idx) => &authority[idx + 1..],
        None => authority,
    };
    let (host, port_str) = host_port
        .rsplit_once(':')
        .ok_or_else(|| format!("missing port in {url}"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|e| format!("invalid port in {url}: {e}"))?;

    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect {url}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("set_write_timeout: {e}"))?;

    let mut req = format!(
        "{method} {path} HTTP/1.0\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);

    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write {url}: {e}"))?;
    stream.flush().map_err(|e| format!("flush {url}: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read {url}: {e}"))?;
    let text = String::from_utf8_lossy(&raw);
    let (head, resp_body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("malformed HTTP response from {url}"))?;
    let status_line = head.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("missing status code in {status_line}"))?
        .parse()
        .map_err(|e| format!("parse status code: {e}"))?;
    Ok((status, resp_body.to_owned()))
}

/// D-34 / R-M2b-49 headless Chrome process measurement result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChromePipeMeasurement {
    pub product: String,
    pub startup_ms: u64,
    pub pipe_close_exit_ms: u64,
    pub exit_code: Option<i32>,
    pub session_member_count: u64,
    pub outside_session_count: usize,
    pub remaining_after_exit_count: usize,
    pub exited_on_pipe_close: bool,
}

/// Runs `integrations/browser-helper/chrome_pipe_probe.cjs` against the pinned
/// Chrome for Testing build and returns [`ChromePipeMeasurement`].
pub fn measure_chrome_pipe_and_session() -> Result<ChromePipeMeasurement, String> {
    let runtime = resolve_browser_runtime(&browser_versions_path())?;
    let script = repo_root().join("integrations/browser-helper/chrome_pipe_probe.cjs");
    let out = Command::new(&runtime.node_exe)
        .arg(&script)
        .arg(&runtime.chrome_exe)
        .output()
        .map_err(|e| format!("run chrome_pipe_probe.cjs: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "chrome_pipe_probe failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let v: Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("parse chrome_pipe_probe json: {e}"))?;
    Ok(ChromePipeMeasurement {
        product: v
            .get("product")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        startup_ms: v.get("startup_ms").and_then(Value::as_u64).unwrap_or(0),
        pipe_close_exit_ms: v
            .get("pipe_close_exit_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        exit_code: v
            .get("exit_code")
            .and_then(Value::as_i64)
            .and_then(|n| i32::try_from(n).ok()),
        session_member_count: v
            .get("session_member_count")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        outside_session_count: v
            .get("outside_session")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        remaining_after_exit_count: v
            .get("remaining_after_exit")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        exited_on_pipe_close: v
            .get("exited_on_pipe_close")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// SI-16 cookie-scope probe result with the pinned Chrome for Testing build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieScopeReport {
    pub origin_1_local_storage_set: bool,
    pub same_host_other_port_cookie_present: bool,
    pub same_host_other_port_local_storage_isolated: bool,
    pub other_subdomain_cookie_present: bool,
    pub other_subdomain_local_storage_isolated: bool,
    pub bg_fetch_same_host_other_port_cookie_present: bool,
    pub bg_fetch_other_subdomain_cookie_present: bool,
    pub separate_context_same_origin_cookie_present: bool,
    pub separate_context_same_origin_local_storage_isolated: bool,
}

/// Runs `integrations/browser-helper/cookie_scope_probe.cjs` with the pinned
/// Node, Playwright, and Chrome for Testing builds to reproduce SI-16.
pub fn run_cookie_scope_probe() -> Result<CookieScopeReport, String> {
    let runtime = resolve_browser_runtime(&browser_versions_path())?;
    let script = repo_root().join("integrations/browser-helper/cookie_scope_probe.cjs");
    let out = Command::new(&runtime.node_exe)
        .arg(&script)
        .arg(&runtime.helper_modules)
        .arg(&runtime.chrome_exe)
        .output()
        .map_err(|e| format!("run cookie_scope_probe.cjs: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cookie_scope_probe failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let v: Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("parse cookie_scope_probe json: {e}"))?;
    let b = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
    Ok(CookieScopeReport {
        origin_1_local_storage_set: b("origin_1_local_storage_set"),
        same_host_other_port_cookie_present: b("same_host_other_port_cookie_present"),
        same_host_other_port_local_storage_isolated: b(
            "same_host_other_port_local_storage_isolated",
        ),
        other_subdomain_cookie_present: b("other_subdomain_cookie_present"),
        other_subdomain_local_storage_isolated: b("other_subdomain_local_storage_isolated"),
        bg_fetch_same_host_other_port_cookie_present: b(
            "bg_fetch_same_host_other_port_cookie_present",
        ),
        bg_fetch_other_subdomain_cookie_present: b("bg_fetch_other_subdomain_cookie_present"),
        separate_context_same_origin_cookie_present: b(
            "separate_context_same_origin_cookie_present",
        ),
        separate_context_same_origin_local_storage_isolated: b(
            "separate_context_same_origin_local_storage_isolated",
        ),
    })
}
