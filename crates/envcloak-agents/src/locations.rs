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

/// The catalog for one home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locations {
    home: PathBuf,
    claude_dir: PathBuf,
    claude_json: PathBuf,
    codex_home: PathBuf,
    xdg_config: PathBuf,
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
        Ok(Locations {
            home,
            claude_dir,
            claude_json,
            codex_home,
            xdg_config,
        })
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Claude Code's directory: `$CLAUDE_CONFIG_DIR`, else `~/.claude`.
    pub fn claude_dir(&self) -> &Path {
        &self.claude_dir
    }

    /// Claude Code's own state file, which holds its user-scope MCP servers
    /// and which it rewrites on every start: EnvCloak reads it and changes
    /// it only through `claude mcp` (D-16).
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

    fn src(path: PathBuf, format: ConfigFormat, kind: SourceKind, label: &str) -> ConfigSource {
        ConfigSource {
            path,
            format,
            source_kind: kind,
            label: label.to_owned(),
        }
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

    /// The stores a pasted or printed value can reach (D-15; Map C §4),
    /// for the tier-1 hosts.
    pub fn transcript_sources(&self) -> Vec<ConfigSource> {
        use ConfigFormat::{Jsonl, Raw};
        use SourceKind::{Database, FileHistory, History, PasteCache, Transcript};
        let c = &self.claude_dir;
        let x = &self.codex_home;
        vec![
            Self::src(
                c.join("projects"),
                Jsonl,
                Transcript,
                "Claude Code transcripts",
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
            Self::src(x.join("log"), Raw, Transcript, "Codex logs"),
            Self::src(
                x.clone(),
                Raw,
                Database,
                "Codex SQLite state (*.sqlite, not scanned)",
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
