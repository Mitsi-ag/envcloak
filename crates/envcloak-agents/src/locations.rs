//! Where each agent host keeps its configuration and its stores (M2 plan
//! D-02, M2-08; Map C §2, §4): the host, version and path catalog. This is
//! the only place host paths are named. What a scanner reads it emits as
//! the scanner's own neutral descriptors
//! ([`envcloak_scan::source::ConfigSource`]), so `envcloak-scan` never
//! depends on this crate (`scripts/check-crate-graph.py`).
//!
//! The paths follow the hosts' documented variables: `CLAUDE_CONFIG_DIR`
//! moves Claude Code's directory and its `.claude.json`, `CODEX_HOME`
//! moves Codex's, and `XDG_CONFIG_HOME` moves the hosts that keep their
//! configuration there (OpenCode, Goose). Paths are absolute; a source may
//! name a directory, whose files of its format the scanner reads.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use envcloak_scan::source::{ConfigFormat, ConfigSource, SourceKind};

/// The host versions a setting that loosens a host's sandbox was measured
/// on, by host id (M2-04, and `m2_story`'s
/// `codex_reaches_the_socket_and_nothing_else_after_install` on each pin):
/// Codex's socket allowance turns command networking on and leaves it to
/// the proxy settings to limit it to EnvCloak's socket, which another
/// version may read otherwise, so only these get it.
pub const SOCKET_ALLOWANCE_QUALIFIED: &[(&str, &str)] = &[("codex", "0.159.2")];

/// Whether `host` at `version` is one the socket allowance was measured
/// on.
pub fn socket_allowance_qualified(host: crate::hook::Host, version: &str) -> bool {
    SOCKET_ALLOWANCE_QUALIFIED
        .iter()
        .any(|(h, v)| *h == host.id() && *v == version)
}

/// The catalog for one home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locations {
    home: PathBuf,
    claude_dir: PathBuf,
    claude_json: PathBuf,
    codex_home: PathBuf,
    xdg_config: PathBuf,
    /// Where Claude Code makes its per-user temporary directory:
    /// `CLAUDE_CODE_TMPDIR`, else `/tmp` (2.1.280 does not read `TMPDIR`
    /// for it, M2-04).
    claude_tmp: PathBuf,
    /// Codex's temporary directory, `TMPDIR` else `/tmp` (Rust's
    /// `temp_dir`).
    tmp: PathBuf,
    /// Codex's system directory, `/etc/codex` (its system, legacy managed
    /// and requirements files): another only in tests
    /// ([`Locations::with_system_dirs`]).
    codex_system: PathBuf,
    /// macOS's managed preferences, where a device profile puts the
    /// settings Codex reads from `com.openai.codex` (pinned 0.159.2,
    /// `codex-rs/config/src/loader/macos.rs`).
    managed_preferences: PathBuf,
}

/// Why the catalog could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoHome;

fn absolute(v: Option<OsString>) -> Option<PathBuf> {
    v.map(PathBuf::from).filter(|p| p.is_absolute())
}

impl Locations {
    /// The catalog for this process's environment.
    ///
    /// # Errors
    /// When `HOME` is unset or not absolute.
    pub fn from_env() -> Result<Locations, NoHome> {
        Locations::new(&|k| std::env::var_os(k))
    }

    /// The catalog for the environment `env` describes.
    ///
    /// # Errors
    /// When `HOME` is unset or not absolute.
    pub fn new(env: &dyn Fn(&str) -> Option<OsString>) -> Result<Locations, NoHome> {
        let home = absolute(env("HOME")).ok_or(NoHome)?;
        let custom = absolute(env("CLAUDE_CONFIG_DIR"));
        let claude_dir = custom.clone().unwrap_or_else(|| home.join(".claude"));
        let claude_json =
            custom.map_or_else(|| home.join(".claude.json"), |d| d.join(".claude.json"));
        let codex_home = absolute(env("CODEX_HOME")).unwrap_or_else(|| home.join(".codex"));
        let xdg_config = absolute(env("XDG_CONFIG_HOME")).unwrap_or_else(|| home.join(".config"));
        let claude_tmp =
            absolute(env("CLAUDE_CODE_TMPDIR")).unwrap_or_else(|| PathBuf::from("/tmp"));
        let tmp = absolute(env("TMPDIR")).unwrap_or_else(|| PathBuf::from("/tmp"));
        Ok(Locations {
            home,
            claude_dir,
            claude_json,
            codex_home,
            xdg_config,
            claude_tmp,
            tmp,
            codex_system: PathBuf::from("/etc/codex"),
            managed_preferences: PathBuf::from("/Library/Managed Preferences"),
        })
    }

    /// The same catalog with Codex's system directory and the managed
    /// preferences directory elsewhere: for tests, which cannot write
    /// `/etc/codex` or `/Library/Managed Preferences`.
    #[must_use]
    pub fn with_system_dirs(mut self, codex_system: PathBuf, managed_preferences: PathBuf) -> Self {
        self.codex_system = codex_system;
        self.managed_preferences = managed_preferences;
        self
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Claude Code's directory: `$CLAUDE_CONFIG_DIR`, else `~/.claude`.
    pub fn claude_dir(&self) -> &Path {
        &self.claude_dir
    }

    /// Claude Code's own state file, which holds its user-scope MCP servers
    /// and which it rewrites itself: EnvCloak changes its MCP server entry
    /// there through its writer, under D-16's rules.
    pub fn claude_json(&self) -> &Path {
        &self.claude_json
    }

    /// Claude Code's user settings (hooks, permissions, sandbox).
    pub fn claude_settings(&self) -> PathBuf {
        self.claude_dir.join("settings.json")
    }

    /// Claude Code's user instructions.
    pub fn claude_instructions(&self) -> PathBuf {
        self.claude_dir.join("CLAUDE.md")
    }

    /// Codex's directory: `$CODEX_HOME`, else `~/.codex`.
    pub fn codex_home(&self) -> &Path {
        &self.codex_home
    }

    /// Codex's configuration, which it rewrites itself (D-16).
    pub fn codex_config(&self) -> PathBuf {
        self.codex_home.join("config.toml")
    }

    /// Codex's user hooks.
    pub fn codex_hooks(&self) -> PathBuf {
        self.codex_home.join("hooks.json")
    }

    /// Codex's user instructions.
    pub fn codex_instructions(&self) -> PathBuf {
        self.codex_home.join("AGENTS.md")
    }

    /// The file that, when present, Codex reads instead of `AGENTS.md`.
    pub fn codex_instructions_override(&self) -> PathBuf {
        self.codex_home.join("AGENTS.override.md")
    }

    /// EnvCloak's Codex rules file.
    pub fn codex_rules(&self) -> PathBuf {
        self.codex_home.join("rules").join("envcloak.rules")
    }

    /// Codex's system configuration, the lowest layer it merges (pinned
    /// 0.159.2, `codex-rs/config/src/loader/mod.rs`).
    pub fn codex_system_config(&self) -> PathBuf {
        self.codex_system.join("config.toml")
    }

    /// Codex's legacy managed configuration, merged above every other
    /// layer.
    pub fn codex_managed_config(&self) -> PathBuf {
        self.codex_system.join("managed_config.toml")
    }

    /// Codex's requirements, which constrain what the layers may set.
    pub fn codex_requirements(&self) -> PathBuf {
        self.codex_system.join("requirements.toml")
    }

    /// The device profiles that may give Codex managed settings (macOS):
    /// `com.openai.codex` in the managed preferences, for every user and
    /// for each one.
    pub fn codex_managed_preferences(&self) -> Vec<PathBuf> {
        const NAME: &str = "com.openai.codex.plist";
        let mut out = vec![self.managed_preferences.join(NAME)];
        if let Ok(rd) = std::fs::read_dir(&self.managed_preferences) {
            for e in rd.flatten() {
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    out.push(e.path().join(NAME));
                }
            }
        }
        out
    }

    /// Codex's cache of the configuration an organization's workspace
    /// sends it (business, education and enterprise accounts; pinned
    /// 0.159.2, `codex-rs/cloud-config/src/cache.rs`).
    pub fn codex_cloud_config_cache(&self) -> PathBuf {
        self.codex_home.join("cloud-config-bundle-cache.json")
    }

    /// The profile configurations `codex --profile NAME` reads on top of
    /// `config.toml`: `<NAME>.config.toml` in Codex's directory.
    pub fn codex_profile_configs(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.codex_home) {
            for e in rd.flatten() {
                let name = e.file_name();
                let name = name.to_string_lossy();
                if name.len() > ".config.toml".len() && name.ends_with(".config.toml") {
                    out.push(e.path());
                }
            }
        }
        out.sort();
        out
    }

    /// The configuration a project's directory gives Codex (a layer when
    /// the project is trusted).
    pub fn codex_project_config(dir: &Path) -> PathBuf {
        dir.join(".codex").join("config.toml")
    }

    fn src(path: PathBuf, format: ConfigFormat, kind: SourceKind, label: &str) -> ConfigSource {
        ConfigSource {
            path,
            format,
            source_kind: kind,
            label: label.to_owned(),
            names: None,
        }
    }

    /// A source of the files directly in `dir` whose names hold `names`.
    fn named(
        dir: PathBuf,
        names: &str,
        format: ConfigFormat,
        kind: SourceKind,
        label: &str,
    ) -> ConfigSource {
        ConfigSource {
            names: Some(names.to_owned()),
            ..Self::src(dir, format, kind, label)
        }
    }

    /// Claude Code's per-user temporary directory: `claude-<uid>` in
    /// `CLAUDE_CODE_TMPDIR`, else in `/tmp`.
    pub fn claude_tmp_dir(&self) -> PathBuf {
        self.claude_tmp
            .join(format!("claude-{}", envcloak_sys::effective_uid()))
    }

    /// The configuration files in the home that can hold an MCP server's
    /// literal keys, for every catalog agent with a documented one (Map C
    /// §3 item 8), and Claude Code's copies of its own.
    pub fn config_sources(&self) -> Vec<ConfigSource> {
        use ConfigFormat::{Json, Toml, Yaml};
        use SourceKind::{HostBackup, McpConfig};
        let h = &self.home;
        vec![
            Self::src(
                self.claude_json.clone(),
                Json,
                McpConfig,
                "Claude Code user config",
            ),
            Self::src(
                self.claude_settings(),
                Json,
                McpConfig,
                "Claude Code user settings",
            ),
            Self::src(
                self.claude_dir.join("backups"),
                Json,
                HostBackup,
                "Claude Code config backups",
            ),
            Self::src(self.codex_config(), Toml, McpConfig, "Codex config"),
            Self::src(
                h.join(".cursor/mcp.json"),
                Json,
                McpConfig,
                "Cursor MCP config",
            ),
            Self::src(
                h.join(".gemini/settings.json"),
                Json,
                McpConfig,
                "Gemini CLI settings",
            ),
            Self::src(
                h.join(".copilot/mcp-config.json"),
                Json,
                McpConfig,
                "Copilot CLI MCP config",
            ),
            Self::src(
                h.join(".kimi-code/mcp.json"),
                Json,
                McpConfig,
                "Kimi Code MCP config",
            ),
            Self::src(
                h.join(".kimi/mcp.json"),
                Json,
                McpConfig,
                "Kimi CLI MCP config",
            ),
            Self::src(
                h.join(".qwen/settings.json"),
                Json,
                McpConfig,
                "Qwen Code settings",
            ),
            Self::src(
                self.xdg_config.join("opencode/opencode.json"),
                Json,
                McpConfig,
                "OpenCode config",
            ),
            Self::src(
                self.xdg_config.join("goose/config.yaml"),
                Yaml,
                McpConfig,
                "Goose config",
            ),
        ]
    }

    /// The MCP configuration files a project can hold (Map C §3 item 8).
    pub fn project_config_sources(project: &Path) -> Vec<ConfigSource> {
        use ConfigFormat::{Json, Toml};
        use SourceKind::McpConfig;
        vec![
            Self::src(
                project.join(".mcp.json"),
                Json,
                McpConfig,
                "project MCP config (Claude Code, Copilot CLI)",
            ),
            Self::src(
                project.join(".cursor/mcp.json"),
                Json,
                McpConfig,
                "project Cursor MCP config",
            ),
            Self::src(
                project.join(".gemini/settings.json"),
                Json,
                McpConfig,
                "project Gemini CLI settings",
            ),
            Self::src(
                project.join(".vscode/mcp.json"),
                Json,
                McpConfig,
                "project VS Code MCP config",
            ),
            Self::src(
                project.join(".github/mcp.json"),
                Json,
                McpConfig,
                "project Copilot MCP config",
            ),
            Self::src(
                project.join("opencode.json"),
                Json,
                McpConfig,
                "project OpenCode config",
            ),
            Self::src(
                project.join(".codex/config.toml"),
                Toml,
                McpConfig,
                "project Codex config",
            ),
        ]
    }

    /// The stores a pasted or printed value can reach, for the tier-1 hosts
    /// (D-15; Map C section 4; and every store M2-04 saw the pinned
    /// versions write, `envcloak_testkit::transcripts`: Codex review, the
    /// catalog left out Claude Code's `debug/`, `plans/` and temporary
    /// directory, Codex's `hook_outputs/`, and the text files in Claude
    /// Code's `projects/`). `tests/catalog_graph.rs` keeps this equal to
    /// both lists.
    pub fn transcript_sources(&self) -> Vec<ConfigSource> {
        use ConfigFormat::{Json, Jsonl, Mixed, Raw};
        use SourceKind::{
            Database, FileHistory, History, HostBackup, Log, PasteCache, Session, Temporary,
            Transcript,
        };
        let c = &self.claude_dir;
        let x = &self.codex_home;
        vec![
            Self::src(
                c.join("projects"),
                Mixed,
                Transcript,
                "Claude Code transcripts and tool results",
            ),
            Self::src(
                c.join("history.jsonl"),
                Jsonl,
                History,
                "Claude Code prompt history",
            ),
            Self::src(
                c.join("paste-cache"),
                Raw,
                PasteCache,
                "Claude Code paste cache",
            ),
            Self::src(
                c.join("file-history"),
                Raw,
                FileHistory,
                "Claude Code file history",
            ),
            Self::src(c.join("plans"), Raw, Session, "Claude Code plans"),
            Self::src(c.join("sessions"), Raw, Session, "Claude Code sessions"),
            Self::src(
                c.join("session-env"),
                Raw,
                Session,
                "Claude Code session environments",
            ),
            Self::src(
                c.join("shell-snapshots"),
                Raw,
                Session,
                "Claude Code shell snapshots",
            ),
            Self::src(c.join("todos"), Raw, Session, "Claude Code to-do lists"),
            Self::src(c.join("debug"), Raw, Log, "Claude Code debug logs"),
            Self::src(c.join("telemetry"), Raw, Log, "Claude Code telemetry"),
            Self::named(
                self.claude_json
                    .parent()
                    .map_or_else(|| self.home.clone(), Path::to_path_buf),
                ".claude.json.backup",
                Json,
                HostBackup,
                "Claude Code config backups beside .claude.json",
            ),
            Self::src(
                self.claude_tmp_dir(),
                Raw,
                Temporary,
                "Claude Code temporary files (command output so far, images, scratchpad)",
            ),
            Self::named(
                self.claude_tmp.clone(),
                "-cwd",
                Raw,
                Temporary,
                "Claude Code working-directory files",
            ),
            Self::src(x.join("sessions"), Jsonl, Transcript, "Codex sessions"),
            Self::src(
                x.join("archived_sessions"),
                Jsonl,
                Transcript,
                "Codex archived sessions",
            ),
            Self::src(
                x.join("history.jsonl"),
                Jsonl,
                History,
                "Codex prompt history",
            ),
            Self::src(x.join("log"), Raw, Log, "Codex logs"),
            Self::src(
                x.join("shell_snapshots"),
                Raw,
                Session,
                "Codex shell snapshots",
            ),
            Self::src(x.join("memories"), Raw, Session, "Codex memories"),
            Self::named(
                x.clone(),
                ".sqlite",
                Raw,
                Database,
                "Codex SQLite state (not scanned)",
            ),
            Self::src(
                self.tmp.join("hook_outputs"),
                Raw,
                Temporary,
                "Codex hook outputs",
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every version the socket allowance is written for is a pinned one,
    /// which CI's egress test (`m2_story`) measures it on.
    #[test]
    fn the_socket_allowance_is_qualified_on_pinned_versions_only() {
        for (host, version) in SOCKET_ALLOWANCE_QUALIFIED {
            assert!(
                crate::probe::model::qualified(host, version),
                "{host} {version}"
            );
        }
        assert!(socket_allowance_qualified(
            crate::hook::Host::Codex,
            "0.159.2"
        ));
        assert!(!socket_allowance_qualified(
            crate::hook::Host::Codex,
            "0.159.3"
        ));
        assert!(!socket_allowance_qualified(
            crate::hook::Host::ClaudeCode,
            "0.159.2"
        ));
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[test]
    fn the_hosts_variables_move_their_files() {
        let l = Locations::new(&env(&[("HOME", "/h")])).unwrap_or_else(|_| panic!("home"));
        assert_eq!(l.claude_settings(), Path::new("/h/.claude/settings.json"));
        assert_eq!(l.claude_json(), Path::new("/h/.claude.json"));
        assert_eq!(l.codex_config(), Path::new("/h/.codex/config.toml"));
        let l = Locations::new(&env(&[
            ("HOME", "/h"),
            ("CLAUDE_CONFIG_DIR", "/c"),
            ("CODEX_HOME", "/x"),
            ("XDG_CONFIG_HOME", "relative"),
        ]))
        .unwrap_or_else(|_| panic!("home"));
        assert_eq!(l.claude_settings(), Path::new("/c/settings.json"));
        assert_eq!(l.claude_json(), Path::new("/c/.claude.json"));
        assert_eq!(l.codex_rules(), Path::new("/x/rules/envcloak.rules"));
        assert!(
            l.config_sources()
                .iter()
                .any(|s| s.path == Path::new("/h/.config/opencode/opencode.json"))
        );
        assert_eq!(Locations::new(&env(&[("HOME", "rel")])), Err(NoHome));
        assert_eq!(Locations::new(&env(&[])), Err(NoHome));
    }

    #[test]
    fn every_source_is_absolute_and_labelled_once() {
        let l = Locations::new(&env(&[("HOME", "/h")])).unwrap_or_else(|_| panic!("home"));
        let mut all = l.config_sources();
        all.extend(l.transcript_sources());
        all.extend(Locations::project_config_sources(Path::new("/p")));
        let mut labels: Vec<&str> = all.iter().map(|s| s.label.as_str()).collect();
        assert!(all.iter().all(|s| s.path.is_absolute()));
        let n = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), n);
    }
}
