pub mod claude;
pub mod codex;
pub mod copilot;
pub mod cursor;
pub mod gemini;
pub mod kimi;
pub mod opencode;
pub mod update;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use envcloak_client::fail::Failure;
use envcloak_client::managed::{
    host_allowed_for_header, refuse_key_shaped_server, register as client_register,
};
use envcloak_client::render::looks_like_value;
use envcloak_core::SecretBytes;
use envcloak_ipc::WireSecret;
use envcloak_ipc::proto::{
    AddParams, BackupBeginParams, BackupPlanFile, ImportCommitParams, ImportEntry, ImportParams,
    ImportScope, LaunchDeclParams, MachineScope, MachineSource, ManagedRegisterParams,
    ManagedServerDecl,
};
use envcloak_ipc::view::{ClassificationView, LaunchReceiptView};
use envcloak_policy::managed::{
    CodeSelecting, DeclError, bridge_binding_name, check_declaration, is_code_selecting,
};
use envcloak_scan::first_run::secret_copy;
use envcloak_scan::source::{ConfigFormat, ConfigSource, SourceKind};
use envcloak_scan::{
    FileStamp, MAX_DOTENV, MIN_AGE, ScanErrorKind, open_root, pause_point, read_plain,
    replace_atomically, scan_config_sources,
};
use envcloak_sys::InUse;

use crate::detect::find_on_path;
use crate::jsonedit::Doc;
use crate::locations::Locations;
use crate::writer::{Journal, MAX_FILE, MAX_HOST_STATE, Stamp, State, StateFile, sha256_hex};

pub use update::{
    BackupMigrationRecord, MigratedServerRecord, MigrationRegistry, UndoReport, UpdateReport,
    lookup_launch_id, plan_update, undo, update,
};

const D17_HELPER_OPT_INS: [&str; 4] = [
    "headersHelper",
    "bearer_token_env_var",
    "http_headers_helper",
    "env_http_headers",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateConsent {
    pub startup_timeout: bool,
}

pub struct MigrateProof<'a> {
    pub loc: &'a Locations,
    pub data_dir: PathBuf,
    pub project_dir: PathBuf,
    pub path_env: OsString,
    pub envcloak_bin: PathBuf,
    pub connect: &'a dyn Fn() -> Result<envcloak_ipc::Client, Failure>,
    pub passphrase: Option<SecretBytes>,
    pub claims: Vec<String>,
    pub expected_statement_digest: Option<String>,
    pub created_by_agent: bool,
    pub unrecorded: bool,
    pub enforce_min_age: bool,
}

impl<'a> MigrateProof<'a> {
    pub fn new(
        loc: &'a Locations,
        data_dir: PathBuf,
        envcloak_bin: PathBuf,
        connect: &'a dyn Fn() -> Result<envcloak_ipc::Client, Failure>,
        passphrase: Option<SecretBytes>,
        claims: Vec<String>,
    ) -> Self {
        Self {
            loc,
            data_dir,
            project_dir: loc.home().to_path_buf(),
            path_env: std::env::var_os("PATH").unwrap_or_default(),
            envcloak_bin,
            connect,
            passphrase,
            claims,
            expected_statement_digest: None,
            created_by_agent: false,
            unrecorded: false,
            enforce_min_age: true,
        }
    }
}

impl fmt::Debug for MigrateProof<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MigrateProof")
            .field("data_dir", &self.data_dir)
            .field("project_dir", &self.project_dir)
            .field("envcloak_bin", &self.envcloak_bin)
            .field("enforce_min_age", &self.enforce_min_age)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum MigrateError {
    Client(Failure),
    MissingPassphrase,
    MissingTool {
        tool: String,
        detail: String,
    },
    ExternalToolFailed {
        tool: String,
        detail: String,
    },
    InvalidConfig {
        path: PathBuf,
        reason: String,
    },
    DisallowedHost {
        server: String,
        header: String,
        host: String,
    },
    OpenElsewhere {
        path: PathBuf,
    },
    RecentlyChanged {
        path: PathBuf,
        agent: String,
    },
    Changed {
        path: PathBuf,
    },
    HardLinked {
        path: PathBuf,
    },
    RestoreRefused {
        path: PathBuf,
        reason: String,
    },
    ServerNotFound {
        agent: String,
        server: String,
    },
    UnmigratedServer {
        server: String,
    },
    StatementMismatch,
    Io {
        path: PathBuf,
        message: String,
    },
}

impl fmt::Display for MigrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrateError::Client(fail) => write!(f, "{}", fail.message()),
            MigrateError::MissingPassphrase => {
                write!(
                    f,
                    "a passphrase proof is required to register or update managed MCP servers"
                )
            }
            MigrateError::MissingTool { tool, detail } => {
                write!(f, "required tool `{tool}` was not found: {detail}")
            }
            MigrateError::ExternalToolFailed { tool, detail } => {
                write!(f, "`{tool}` failed: {detail}")
            }
            MigrateError::InvalidConfig { path, reason } => {
                write!(f, "cannot parse {}: {reason}", path.display())
            }
            MigrateError::DisallowedHost {
                server,
                header,
                host,
            } => write!(
                f,
                "refused to migrate {server}: header `{header}` holds a key whose provider does \
                 not allow host `{host}`"
            ),
            MigrateError::OpenElsewhere { path } => write!(
                f,
                "{} is open in another process; quit the host agent before running migrate-mcp",
                path.display()
            ),
            MigrateError::RecentlyChanged { path, agent } => write!(
                f,
                "{} was modified within the last 2 minutes; quit {agent} and wait 2 minutes \
                 before running migrate-mcp",
                path.display()
            ),
            MigrateError::Changed { path } => write!(
                f,
                "{} changed while migrate-mcp was running; nothing was written",
                path.display()
            ),
            MigrateError::HardLinked { path } => write!(
                f,
                "{} has multiple hard links and cannot be rewritten safely",
                path.display()
            ),
            MigrateError::RestoreRefused { path, reason } => {
                write!(f, "refused to restore {}: {reason}", path.display())
            }
            MigrateError::ServerNotFound { agent, server } => {
                write!(f, "MCP server `{agent}/{server}` was not found in config")
            }
            MigrateError::UnmigratedServer { server } => write!(
                f,
                "MCP server `{server}` is not a registered managed stdio launch; run \
                 `envcloak agents migrate-mcp` first"
            ),
            MigrateError::StatementMismatch => write!(
                f,
                "the launch declaration changed since the update statement was shown"
            ),
            MigrateError::Io { path, message } => {
                write!(f, "{}: {message}", path.display())
            }
        }
    }
}

impl std::error::Error for MigrateError {}

impl MigrateError {
    pub fn to_failure(&self) -> Failure {
        match self {
            MigrateError::Client(f) => f.clone(),
            MigrateError::MissingPassphrase => Failure::new("no_terminal", self.to_string()),
            MigrateError::MissingTool { .. } | MigrateError::ExternalToolFailed { .. } => {
                Failure::new("agents_incomplete", self.to_string())
            }
            MigrateError::InvalidConfig { .. }
            | MigrateError::DisallowedHost { .. }
            | MigrateError::OpenElsewhere { .. }
            | MigrateError::RecentlyChanged { .. }
            | MigrateError::Changed { .. }
            | MigrateError::HardLinked { .. } => Failure::new("incomplete", self.to_string()),
            MigrateError::RestoreRefused { .. } => {
                Failure::new("restore_refused", self.to_string())
            }
            MigrateError::ServerNotFound { .. } | MigrateError::UnmigratedServer { .. } => {
                Failure::new("not_found", self.to_string())
            }
            MigrateError::StatementMismatch => Failure::new("statement_mismatch", self.to_string()),
            MigrateError::Io { .. } => Failure::new("io", self.to_string()),
        }
    }
}

pub struct PlannedSecret {
    pub name: String,
    pub value: SecretBytes,
}

impl Clone for PlannedSecret {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            value: secret_copy(&self.value),
        }
    }
}

impl fmt::Debug for PlannedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlannedSecret")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub enum PlannedRewriteKind {
    Stdio {
        argv: Vec<String>,
        cwd: Option<String>,
        non_secret_env: Vec<(String, String)>,
        secrets: Vec<PlannedSecret>,
    },
    HttpBridge {
        url: String,
        origin: String,
        host: String,
        headers: Vec<PlannedSecret>,
        env_secrets: Vec<PlannedSecret>,
    },
}

#[derive(Debug, Clone)]
pub struct PlannedServerMigration {
    pub agent: String,
    pub server: String,
    pub config_path: PathBuf,
    pub format: ConfigFormat,
    pub codex_needs_startup_timeout: bool,
    pub kind: PlannedRewriteKind,
}

impl PlannedServerMigration {
    pub fn key(&self) -> String {
        format!("{}/{}", self.agent, self.server)
    }

    pub fn transport_name(&self) -> &'static str {
        match &self.kind {
            PlannedRewriteKind::Stdio { .. } => "stdio",
            PlannedRewriteKind::HttpBridge { .. } => "bridge",
        }
    }

    pub fn managed_dir(&self, data_dir: &Path) -> PathBuf {
        data_dir.join("mcp").join(format!(
            "{}-{}",
            update::sanitize_segment(&self.agent),
            update::sanitize_segment(&self.server)
        ))
    }

    pub fn manifest_path(&self, data_dir: &Path) -> PathBuf {
        self.managed_dir(data_dir).join("envcloak.toml")
    }

    pub fn secret_names(&self) -> Vec<String> {
        match &self.kind {
            PlannedRewriteKind::Stdio { secrets, .. } => {
                secrets.iter().map(|s| s.name.clone()).collect()
            }
            PlannedRewriteKind::HttpBridge {
                headers,
                env_secrets,
                ..
            } => headers
                .iter()
                .chain(env_secrets.iter())
                .map(|s| s.name.clone())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualItem {
    pub agent: String,
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    pub reason: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnavailableOptIn {
    pub agent: String,
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    pub opt_in: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct MigratePlan {
    pub rewrites: Vec<PlannedServerMigration>,
    pub manual_items: Vec<ManualItem>,
    pub unavailable_opt_ins: Vec<UnavailableOptIn>,
    pub claude_backups_dir: Option<PathBuf>,
    pub shared_mcp_json_touched: bool,
}

impl MigratePlan {
    pub fn is_empty(&self) -> bool {
        self.rewrites.is_empty()
            && self.manual_items.is_empty()
            && self.unavailable_opt_ins.is_empty()
    }

    pub fn codex_needs_startup_timeout(&self) -> bool {
        self.rewrites
            .iter()
            .any(|r| r.agent == "codex" && r.codex_needs_startup_timeout)
    }

    pub fn filter_agent(&mut self, agent: &str) {
        self.rewrites.retain(|r| r.agent == agent);
        self.manual_items
            .retain(|m| m.agent == agent || m.agent == "unknown");
        self.unavailable_opt_ins.retain(|u| u.agent == agent);
        self.shared_mcp_json_touched = self
            .rewrites
            .iter()
            .any(|r| r.config_path.file_name() == Some(OsStr::new(".mcp.json")));
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedSecretSummary {
    pub server: String,
    pub name: String,
    pub slug: String,
    pub reference: String,
    pub classification: ClassificationView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigratedServerSummary {
    pub agent: String,
    pub server: String,
    pub config_path: PathBuf,
    pub manifest_path: PathBuf,
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_id: Option<String>,
    pub policy_id: String,
    pub rewritten_command: String,
    pub rewritten_args: Vec<String>,
    pub codex_startup_timeout_set: bool,
    pub standing_eligible: bool,
    pub receipt: LaunchReceiptView,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrateReport {
    pub committed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<String>,
    pub servers: Vec<MigratedServerSummary>,
    pub receipts: Vec<LaunchReceiptView>,
    pub imported_items: Vec<ImportedSecretSummary>,
    pub manual_items: Vec<ManualItem>,
    pub unavailable_opt_ins: Vec<UnavailableOptIn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_backups_note: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reprobe_agents: Vec<String>,
    pub next_steps: Vec<String>,
}

impl MigrateReport {
    pub fn complete(&self) -> bool {
        self.manual_items.is_empty()
    }
}

pub fn plan(loc: &Locations) -> MigratePlan {
    plan_with_project(loc, None)
}

pub fn plan_with_project(loc: &Locations, project: Option<&Path>) -> MigratePlan {
    let mut sources = loc.config_sources();
    for proj_src in Locations::project_config_sources(loc.home()) {
        if !sources.iter().any(|s| s.path == proj_src.path) {
            sources.push(proj_src);
        }
    }
    if let Some(proj) = project {
        let norm_proj = normalize_scan_path(loc, proj);
        if norm_proj != loc.home() {
            for proj_src in Locations::project_config_sources(&norm_proj) {
                if !sources.iter().any(|s| s.path == proj_src.path) {
                    sources.push(proj_src);
                }
            }
        }
    }

    let scan_report = scan_config_sources(&sources).unwrap_or_default();
    let mut out = MigratePlan::default();

    let claude_backups = loc.claude_dir().join("backups");
    if claude_backups.exists() {
        out.claude_backups_dir = Some(claude_backups);
    }

    let mut issue_paths = BTreeSet::new();
    for issue in &scan_report.issues {
        let p = normalize_scan_path(loc, &issue.source.path);
        let Some(agent) = agent_for_path(&sources, &p) else {
            continue;
        };
        issue_paths.insert(p.clone());
        let detail = match issue.reason {
            "unsupported_format" => format!(
                "{} uses an unsupported format ({}) that cannot be rewritten preserving comments; \
                 migrate manually",
                p.display(),
                issue.reason
            ),
            "invalid_json" => format!(
                "{} is not strict JSON (JSONC comments or trailing commas are refused); fix syntax \
                 or migrate manually",
                p.display()
            ),
            "invalid_toml" => format!(
                "{} is not valid TOML; fix syntax or migrate manually",
                p.display()
            ),
            other => format!(
                "{} could not be migrated automatically ({other}); migrate manually",
                p.display()
            ),
        };
        push_manual_unique(
            &mut out.manual_items,
            ManualItem {
                agent: agent.to_string(),
                path: p,
                server: issue.source.object.clone(),
                reason: issue.reason.to_string(),
                detail,
            },
        );
    }

    for note in &scan_report.notes {
        let p = normalize_scan_path(loc, &note.source.path);
        let agent = agent_for_path(&sources, &p).unwrap_or_else(|| {
            if p.file_name() == Some(OsStr::new("mcp-secrets")) {
                "copilot"
            } else if p.file_name() == Some(OsStr::new("auth.json")) {
                "opencode"
            } else {
                "unknown"
            }
        });
        if note.reason == "manual_credentials" {
            push_manual_unique(
                &mut out.manual_items,
                ManualItem {
                    agent: agent.to_string(),
                    path: p.clone(),
                    server: None,
                    reason: "manual_credentials".to_string(),
                    detail: format!(
                        "{} is an external credential store ({}) that must be migrated manually",
                        p.display(),
                        agent
                    ),
                },
            );
        }
    }

    let mut visited_files = BTreeSet::new();
    for src in &sources {
        if src.source_kind != SourceKind::McpConfig {
            continue;
        }
        if !visited_files.insert(src.path.clone()) {
            continue;
        }
        if issue_paths.contains(&src.path) {
            continue;
        }
        let Some(agent) = agent_for_label(&src.label) else {
            continue;
        };
        if !src.path.exists() {
            continue;
        }
        match src.format {
            ConfigFormat::Json => {
                inspect_json_mcp_file(loc, agent, &src.path, &mut out);
            }
            ConfigFormat::Toml => {
                inspect_toml_mcp_file(loc, agent, &src.path, &mut out);
            }
            ConfigFormat::Yaml => {
                push_manual_unique(
                    &mut out.manual_items,
                    ManualItem {
                        agent: agent.to_string(),
                        path: src.path.clone(),
                        server: None,
                        reason: "unsupported_format".to_string(),
                        detail: format!(
                            "{} uses YAML and must be migrated manually",
                            src.path.display()
                        ),
                    },
                );
            }
            _ => {}
        }
    }

    out.shared_mcp_json_touched = out
        .rewrites
        .iter()
        .any(|r| r.config_path.file_name() == Some(OsStr::new(".mcp.json")));

    out
}

fn push_manual_unique(list: &mut Vec<ManualItem>, item: ManualItem) {
    if !list
        .iter()
        .any(|m| m.path == item.path && m.server == item.server && m.reason == item.reason)
    {
        list.push(item);
    }
}

fn push_opt_in_unique(list: &mut Vec<UnavailableOptIn>, item: UnavailableOptIn) {
    if !list
        .iter()
        .any(|u| u.path == item.path && u.server == item.server && u.opt_in == item.opt_in)
    {
        list.push(item);
    }
}

fn normalize_scan_path(loc: &Locations, p: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    if let Ok(rest) = p.strip_prefix("/private/tmp")
        && loc.home().starts_with("/tmp")
    {
        return Path::new("/tmp").join(rest);
    }
    #[cfg(target_os = "macos")]
    if let Ok(rest) = p.strip_prefix("/private/var")
        && loc.home().starts_with("/var")
    {
        return Path::new("/var").join(rest);
    }
    let _ = loc;
    p.to_path_buf()
}

fn agent_for_path(sources: &[ConfigSource], path: &Path) -> Option<&'static str> {
    for src in sources {
        if src.path == path
            && matches!(
                src.source_kind,
                SourceKind::McpConfig | SourceKind::Credentials
            )
        {
            return agent_for_label(&src.label);
        }
    }
    if let Ok(canon) = fs::canonicalize(path) {
        for src in sources {
            if matches!(
                src.source_kind,
                SourceKind::McpConfig | SourceKind::Credentials
            ) && fs::canonicalize(&src.path).ok().as_ref() == Some(&canon)
            {
                return agent_for_label(&src.label);
            }
        }
    }
    None
}

fn agent_for_label(label: &str) -> Option<&'static str> {
    if label.contains("Claude Code") {
        Some("claude-code")
    } else if label.contains("Codex") && !label.contains("CodexBar") {
        Some("codex")
    } else if label.contains("Cursor") {
        Some("cursor")
    } else if label.contains("Gemini") {
        Some("gemini")
    } else if label.contains("Copilot") {
        Some("copilot")
    } else if label.contains("Kimi") {
        Some("kimi")
    } else if label.contains("OpenCode") {
        Some("opencode")
    } else if label.contains("Goose") {
        Some("goose")
    } else if label.contains("Qwen") {
        Some("qwen")
    } else if label.contains("VS Code") {
        Some("vscode")
    } else {
        None
    }
}

fn inspect_json_mcp_file(loc: &Locations, agent: &str, path: &Path, out: &mut MigratePlan) {
    let Ok(raw) = fs::read_to_string(path) else {
        return;
    };
    if Doc::parse(raw.as_bytes()).is_err() {
        push_manual_unique(
            &mut out.manual_items,
            ManualItem {
                agent: agent.to_string(),
                path: path.to_path_buf(),
                server: None,
                reason: "invalid_json".to_string(),
                detail: format!(
                    "{} is not strict JSON (JSONC comments or trailing commas are refused)",
                    path.display()
                ),
            },
        );
        return;
    }
    let Ok(root_val) = serde_json::from_str::<Value>(&raw) else {
        push_manual_unique(
            &mut out.manual_items,
            ManualItem {
                agent: agent.to_string(),
                path: path.to_path_buf(),
                server: None,
                reason: "invalid_json".to_string(),
                detail: format!("{} is not valid JSON", path.display()),
            },
        );
        return;
    };
    let Some(root_obj) = root_val.as_object() else {
        return;
    };

    for opt_in in D17_HELPER_OPT_INS {
        if root_obj.contains_key(opt_in) {
            push_opt_in_unique(
                &mut out.unavailable_opt_ins,
                UnavailableOptIn {
                    agent: agent.to_string(),
                    path: path.to_path_buf(),
                    server: None,
                    opt_in: opt_in.to_string(),
                    detail: format!(
                        "`{opt_in}` in {} is unavailable until M9 (requires a helper grant, which \
                         has no delivery path before M9)",
                        path.display()
                    ),
                },
            );
        }
    }

    let servers_key = if agent == "opencode" && root_obj.contains_key("mcp") {
        "mcp"
    } else if root_obj.contains_key("mcpServers") {
        "mcpServers"
    } else if root_obj.contains_key("mcp_servers") {
        "mcp_servers"
    } else if root_obj.contains_key("mcp") {
        "mcp"
    } else if root_obj.contains_key("servers") {
        "servers"
    } else {
        return;
    };

    let Some(servers_obj) = root_obj.get(servers_key).and_then(Value::as_object) else {
        return;
    };

    for (server_name, srv_val) in servers_obj {
        let Some(srv_obj) = srv_val.as_object() else {
            continue;
        };
        inspect_raw_server(
            loc,
            agent,
            path,
            ConfigFormat::Json,
            server_name,
            &RawServer::from_json(srv_obj),
            false,
            out,
        );
    }
}

fn inspect_toml_mcp_file(loc: &Locations, agent: &str, path: &Path, out: &mut MigratePlan) {
    let Ok(raw) = fs::read_to_string(path) else {
        return;
    };
    let Ok(doc) = raw.parse::<toml_edit::DocumentMut>() else {
        push_manual_unique(
            &mut out.manual_items,
            ManualItem {
                agent: agent.to_string(),
                path: path.to_path_buf(),
                server: None,
                reason: "invalid_toml".to_string(),
                detail: format!("{} is not valid TOML", path.display()),
            },
        );
        return;
    };
    let Some(mcp_table) = doc
        .get("mcp_servers")
        .and_then(toml_edit::Item::as_table_like)
    else {
        return;
    };
    for (server_name, srv_item) in mcp_table.iter() {
        let Some(srv_tbl) = srv_item.as_table_like() else {
            continue;
        };
        let needs_timeout = codex::needs_startup_timeout(&raw, server_name);
        inspect_raw_server(
            loc,
            agent,
            path,
            ConfigFormat::Toml,
            server_name,
            &RawServer::from_toml(srv_tbl),
            needs_timeout,
            out,
        );
    }
}

#[derive(Default)]
struct RawServer {
    command: Option<String>,
    args: Vec<String>,
    cwd: Option<String>,
    url: Option<String>,
    env: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    env_file: Option<String>,
    opt_ins: Vec<String>,
    has_template_or_ref: bool,
    has_manual_ref: bool,
}

impl RawServer {
    fn from_json(obj: &serde_json::Map<String, Value>) -> Self {
        let mut raw = Self::default();
        if let Some(cmd) = obj.get("command").and_then(Value::as_str) {
            raw.command = Some(cmd.to_string());
        } else if let Some(cmd_arr) = obj.get("command").and_then(Value::as_array) {
            let parts: Vec<String> = cmd_arr
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            if let Some((first, rest)) = parts.split_first() {
                raw.command = Some(first.clone());
                raw.args.extend(rest.iter().cloned());
            }
        }
        if let Some(args) = obj.get("args").and_then(Value::as_array) {
            for a in args {
                if let Some(s) = a.as_str() {
                    raw.args.push(s.to_string());
                }
            }
        }
        if let Some(cwd) = obj.get("cwd").and_then(Value::as_str) {
            raw.cwd = Some(cwd.to_string());
        }
        if let Some(url) = obj
            .get("url")
            .or_else(|| obj.get("httpUrl"))
            .and_then(Value::as_str)
        {
            raw.url = Some(url.to_string());
        }
        for env_key in ["env", "environment"] {
            if let Some(env_obj) = obj.get(env_key).and_then(Value::as_object) {
                for (k, v) in env_obj {
                    if let Some(s) = v.as_str() {
                        raw.record_env(k, s);
                    }
                }
            }
        }
        for hdr_key in ["headers", "http_headers"] {
            if let Some(hdr_obj) = obj.get(hdr_key).and_then(Value::as_object) {
                for (k, v) in hdr_obj {
                    if let Some(s) = v.as_str() {
                        raw.record_header(k, s);
                    }
                }
            }
        }
        if let Some(auth_obj) = obj.get("auth").and_then(Value::as_object) {
            for (k, v) in auth_obj {
                if let Some(s) = v.as_str() {
                    let hdr_name = if k.eq_ignore_ascii_case("token")
                        || k.eq_ignore_ascii_case("bearer")
                        || k.eq_ignore_ascii_case("apikey")
                    {
                        "Authorization"
                    } else {
                        k.as_str()
                    };
                    raw.record_header(hdr_name, s);
                }
            }
        }
        for top_secret in ["apiKey", "token", "cookieHeader"] {
            if let Some(s) = obj.get(top_secret).and_then(Value::as_str) {
                let hdr_name = if top_secret == "cookieHeader" {
                    "Cookie"
                } else {
                    "Authorization"
                };
                raw.record_header(hdr_name, s);
            }
        }
        if let Some(ef) = obj.get("envFile").and_then(Value::as_str) {
            raw.env_file = Some(ef.to_string());
        }
        for opt in D17_HELPER_OPT_INS {
            if obj.contains_key(opt) {
                raw.opt_ins.push(opt.to_string());
            }
        }
        raw
    }

    fn from_toml(tbl: &dyn toml_edit::TableLike) -> Self {
        let mut raw = Self::default();
        if let Some(cmd) = tbl.get("command").and_then(toml_edit::Item::as_str) {
            raw.command = Some(cmd.to_string());
        }
        if let Some(args) = tbl.get("args").and_then(toml_edit::Item::as_array) {
            for a in args.iter() {
                if let Some(s) = a.as_str() {
                    raw.args.push(s.to_string());
                }
            }
        }
        if let Some(cwd) = tbl.get("cwd").and_then(toml_edit::Item::as_str) {
            raw.cwd = Some(cwd.to_string());
        }
        if let Some(url) = tbl
            .get("url")
            .or_else(|| tbl.get("httpUrl"))
            .and_then(toml_edit::Item::as_str)
        {
            raw.url = Some(url.to_string());
        }
        for env_key in ["env", "environment"] {
            if let Some(env_tbl) = tbl.get(env_key).and_then(toml_edit::Item::as_table_like) {
                for (k, v) in env_tbl.iter() {
                    if let Some(s) = v.as_str() {
                        raw.record_env(k, s);
                    }
                }
            }
        }
        for hdr_key in ["headers", "http_headers"] {
            if let Some(hdr_tbl) = tbl.get(hdr_key).and_then(toml_edit::Item::as_table_like) {
                for (k, v) in hdr_tbl.iter() {
                    if let Some(s) = v.as_str() {
                        raw.record_header(k, s);
                    }
                }
            }
        }
        if let Some(ef) = tbl.get("envFile").and_then(toml_edit::Item::as_str) {
            raw.env_file = Some(ef.to_string());
        }
        for opt in D17_HELPER_OPT_INS {
            if tbl.contains_key(opt) {
                raw.opt_ins.push(opt.to_string());
            }
        }
        raw
    }

    fn record_env(&mut self, k: &str, v: &str) {
        if v.starts_with("envcloak://") || contains_interpolation(v) {
            self.has_template_or_ref = true;
            if malformed_interpolation(v) {
                self.has_manual_ref = true;
            }
            return;
        }
        self.env.push((k.to_string(), v.to_string()));
    }

    fn record_header(&mut self, k: &str, v: &str) {
        if v.starts_with("envcloak://") || contains_interpolation(v) {
            self.has_template_or_ref = true;
            if malformed_interpolation(v) {
                self.has_manual_ref = true;
            }
            return;
        }
        self.headers.push((k.to_string(), v.to_string()));
    }
}

fn contains_interpolation(v: &str) -> bool {
    v.contains("${")
}

fn malformed_interpolation(v: &str) -> bool {
    let Some(start) = v.find("${") else {
        return false;
    };
    let tail = &v[start + 2..];
    let Some(end) = tail.find('}') else {
        return true;
    };
    let inner = &tail[..end];
    inner.is_empty() || inner.contains('{')
}

#[allow(clippy::too_many_arguments)]
fn inspect_raw_server(
    loc: &Locations,
    agent: &str,
    path: &Path,
    format: ConfigFormat,
    server_name: &str,
    raw: &RawServer,
    codex_needs_startup_timeout: bool,
    out: &mut MigratePlan,
) {
    if is_already_migrated(raw.command.as_deref(), &raw.args) {
        return;
    }

    for opt_in in &raw.opt_ins {
        push_opt_in_unique(
            &mut out.unavailable_opt_ins,
            UnavailableOptIn {
                agent: agent.to_string(),
                path: path.to_path_buf(),
                server: Some(server_name.to_string()),
                opt_in: opt_in.clone(),
                detail: format!(
                    "`{opt_in}` on `{agent}/{server_name}` is unavailable until M9 (requires a \
                     helper grant, which has no delivery path before M9)"
                ),
            },
        );
    }

    if raw
        .command
        .as_deref()
        .is_some_and(arg_contains_secret_literal)
        || raw.args.iter().any(|a| arg_contains_secret_literal(a))
    {
        push_manual_unique(
            &mut out.manual_items,
            ManualItem {
                agent: agent.to_string(),
                path: path.to_path_buf(),
                server: Some(server_name.to_string()),
                reason: "secret_in_args".to_string(),
                detail: format!(
                    "server `{agent}/{server_name}` in {} has a secret literal in `args` and \
                     cannot be migrated automatically; move the secret to an environment variable",
                    path.display()
                ),
            },
        );
        return;
    }

    if let Some((code_var, _)) = raw.env.iter().find(|(k, _)| is_code_selecting(k)) {
        push_manual_unique(
            &mut out.manual_items,
            ManualItem {
                agent: agent.to_string(),
                path: path.to_path_buf(),
                server: Some(server_name.to_string()),
                reason: "code_selecting_env".to_string(),
                detail: format!(
                    "server `{agent}/{server_name}` in {} sets code-selecting environment \
                     variable `{code_var}`, which the daemon refuses; migrate manually",
                    path.display()
                ),
            },
        );
        return;
    }

    if let Some(cmd) = &raw.command
        && let Some(code_reason) =
            check_argv_code_selecting(loc, cmd, &raw.args, raw.cwd.as_deref())
    {
        push_manual_unique(
            &mut out.manual_items,
            ManualItem {
                agent: agent.to_string(),
                path: path.to_path_buf(),
                server: Some(server_name.to_string()),
                reason: "code_selecting_env".to_string(),
                detail: format!(
                    "server `{agent}/{server_name}` in {} uses a code-selecting command or \
                     interpreter option ({code_reason}), which the daemon refuses; migrate manually",
                    path.display()
                ),
            },
        );
        return;
    }

    let mut env_file_secrets = Vec::new();
    if let Some(ef) = &raw.env_file {
        if ef.starts_with("envcloak://") || contains_interpolation(ef) {
            push_manual_unique(
                &mut out.manual_items,
                ManualItem {
                    agent: agent.to_string(),
                    path: path.to_path_buf(),
                    server: Some(server_name.to_string()),
                    reason: "unread_env_file".to_string(),
                    detail: format!(
                        "server `{agent}/{server_name}` in {} references an interpolated envFile \
                         `{ef}` that must be migrated manually",
                        path.display()
                    ),
                },
            );
            return;
        }
        let ef_path = if Path::new(ef).is_absolute() {
            PathBuf::from(ef)
        } else {
            path.parent().unwrap_or_else(|| Path::new(".")).join(ef)
        };
        if let (Some(ef_parent), Some(ef_name)) = (ef_path.parent(), ef_path.file_name())
            && let Ok(ef_root) = open_root(ef_parent)
            && let Ok((ef_bytes, _)) = read_plain(&ef_root, Path::new(ef_name), MAX_DOTENV)
            && let Ok(entries) = envcloak_scan::parse_dotenv(&SecretBytes::copy_from(&ef_bytes))
        {
            for entry in entries {
                if is_code_selecting(entry.name.as_str()) {
                    push_manual_unique(
                        &mut out.manual_items,
                        ManualItem {
                            agent: agent.to_string(),
                            path: path.to_path_buf(),
                            server: Some(server_name.to_string()),
                            reason: "code_selecting_env".to_string(),
                            detail: format!(
                                "server `{agent}/{server_name}` envFile {} sets code-selecting \
                                 variable `{}`",
                                ef_path.display(),
                                entry.name.as_str()
                            ),
                        },
                    );
                    return;
                }
                if entry.kind == envcloak_scan::EntryKind::Plain && !entry.value.is_empty() {
                    env_file_secrets.push(PlannedSecret {
                        name: entry.name.as_str().to_string(),
                        value: entry.value,
                    });
                }
            }
        }
    }

    if let Some(url_str) = &raw.url {
        let mut headers = Vec::new();
        for (h_name, h_val) in &raw.headers {
            if !h_val.is_empty() {
                headers.push(PlannedSecret {
                    name: h_name.clone(),
                    value: SecretBytes::copy_from(h_val.as_bytes()),
                });
            }
        }
        let mut env_secrets = Vec::new();
        for (e_name, e_val) in &raw.env {
            if is_secret_env_pair(e_name, e_val) {
                env_secrets.push(PlannedSecret {
                    name: e_name.clone(),
                    value: SecretBytes::copy_from(e_val.as_bytes()),
                });
            }
        }
        env_secrets.extend(env_file_secrets);
        if headers.is_empty() && env_secrets.is_empty() {
            return;
        }
        let (origin, host) = match parse_bridge_origin(url_str) {
            Ok(pair) => pair,
            Err(_) => {
                push_manual_unique(
                    &mut out.manual_items,
                    ManualItem {
                        agent: agent.to_string(),
                        path: path.to_path_buf(),
                        server: Some(server_name.to_string()),
                        reason: "invalid_bridge_url".to_string(),
                        detail: format!(
                            "server `{agent}/{server_name}` in {} has a URL that cannot be \
                             bridged automatically",
                            path.display()
                        ),
                    },
                );
                return;
            }
        };
        out.rewrites.push(PlannedServerMigration {
            agent: agent.to_string(),
            server: server_name.to_string(),
            config_path: path.to_path_buf(),
            format,
            codex_needs_startup_timeout,
            kind: PlannedRewriteKind::HttpBridge {
                url: url_str.clone(),
                origin,
                host,
                headers,
                env_secrets,
            },
        });
        return;
    }

    let Some(cmd) = &raw.command else {
        return;
    };

    let mut secrets = Vec::new();
    let mut non_secret_env = Vec::new();
    for (k, v) in &raw.env {
        if is_secret_env_pair(k, v) {
            secrets.push(PlannedSecret {
                name: k.clone(),
                value: SecretBytes::copy_from(v.as_bytes()),
            });
        } else {
            non_secret_env.push((k.clone(), v.clone()));
        }
    }
    secrets.extend(env_file_secrets);

    if secrets.is_empty() {
        return;
    }

    let mut argv = Vec::with_capacity(1 + raw.args.len());
    argv.push(cmd.clone());
    argv.extend(raw.args.iter().cloned());

    out.rewrites.push(PlannedServerMigration {
        agent: agent.to_string(),
        server: server_name.to_string(),
        config_path: path.to_path_buf(),
        format,
        codex_needs_startup_timeout,
        kind: PlannedRewriteKind::Stdio {
            argv,
            cwd: raw.cwd.clone(),
            non_secret_env,
            secrets,
        },
    });
}

fn is_already_migrated(command: Option<&str>, args: &[String]) -> bool {
    let Some(cmd) = command else {
        return false;
    };
    let is_envcloak =
        cmd == "envcloak" || Path::new(cmd).file_name() == Some(OsStr::new("envcloak"));
    is_envcloak && args.first().is_some_and(|a| a == "mcp-bridge")
}

fn arg_contains_secret_literal(arg: &str) -> bool {
    if looks_like_value(arg) {
        return true;
    }
    if let Some((_, rhs)) = arg.split_once('=')
        && looks_like_value(rhs)
    {
        return true;
    }
    false
}

fn is_secret_env_pair(name: &str, value: &str) -> bool {
    if value.len() < 8 || value.starts_with("envcloak://") || contains_interpolation(value) {
        return false;
    }
    if looks_like_value(value) {
        return true;
    }
    let upper = name.to_ascii_uppercase();
    [
        "KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "AUTH",
        "BEARER",
        "PRIVATE",
        "COOKIE",
        "SESSION",
        "SIGNING",
        "WEBHOOK",
        "DSN",
    ]
    .iter()
    .any(|kw| upper.contains(kw))
}

fn check_argv_code_selecting(
    loc: &Locations,
    cmd: &str,
    args: &[String],
    cwd: Option<&str>,
) -> Option<&'static str> {
    let sys_path = std::env::var_os("PATH").unwrap_or_default();
    let exe = if Path::new(cmd).is_absolute() {
        PathBuf::from(cmd)
    } else if let Some(found) = find_on_path(cmd, &sys_path) {
        found
    } else {
        let base = Path::new(cmd)
            .file_name()
            .unwrap_or_else(|| OsStr::new(cmd));
        PathBuf::from("/usr/bin").join(base)
    };
    let base_dir = cwd
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| loc.home().to_path_buf());

    let mut test_argv = Vec::with_capacity(1 + args.len());
    test_argv.push(exe.to_string_lossy().into_owned());
    for a in args {
        if !a.starts_with('-') && !Path::new(a).is_absolute() {
            test_argv.push(base_dir.join(a).to_string_lossy().into_owned());
        } else {
            test_argv.push(a.clone());
        }
    }

    let decl = envcloak_core::vault::LaunchDecl {
        argv: test_argv,
        cwd: Some(base_dir.to_string_lossy().into_owned()),
        env: Vec::new(),
        path_env: None,
    };

    match check_declaration(&decl) {
        Err(DeclError::CodeSelecting(CodeSelecting::Variable)) => Some("code_selecting_variable"),
        Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption)) => {
            Some("interpreter_option")
        }
        Err(DeclError::Wrapper) => Some("wrapper_program"),
        Err(DeclError::Disguised) => Some("disguised_launcher"),
        _ => {
            if let Ok(canon) = fs::canonicalize(&exe)
                && matches!(
                    envcloak_policy::managed::refuse_disguised(
                        &decl.argv,
                        &canon.to_string_lossy()
                    ),
                    Err(DeclError::Disguised)
                )
            {
                return Some("disguised_launcher");
            }
            None
        }
    }
}

fn parse_bridge_origin(raw: &str) -> Result<(String, String), &'static str> {
    if raw.is_empty() || raw.len() > 2048 || raw.bytes().any(|b| !b.is_ascii_graphic() || b == b'#')
    {
        return Err("invalid url");
    }
    let (scheme, rest) = if let Some(r) = raw.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = raw.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err("unsupported scheme");
    };
    let split_at = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..split_at];
    if authority.is_empty() || authority.contains('@') {
        return Err("invalid authority");
    }
    let (host_raw, port_raw) = if let Some(after_bracket) = authority.strip_prefix('[') {
        let Some((ipv6, after)) = after_bracket.split_once(']') else {
            return Err("unclosed ipv6");
        };
        if ipv6.is_empty()
            || !ipv6
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return Err("invalid ipv6");
        }
        let port = if after.is_empty() {
            None
        } else if let Some(p) = after.strip_prefix(':') {
            Some(p)
        } else {
            return Err("invalid ipv6 port");
        };
        (format!("[{}]", ipv6.to_ascii_lowercase()), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_ascii_lowercase(), Some(p)),
            None => (authority.to_ascii_lowercase(), None),
        }
    };
    if host_raw.is_empty()
        || (!host_raw.starts_with('[')
            && (!host_raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                || host_raw.starts_with('.')
                || host_raw.ends_with('.')
                || host_raw.contains("..")))
    {
        return Err("invalid host");
    }
    let port = match port_raw {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid port");
            }
            let n = p.parse::<u16>().map_err(|_| "invalid port")?;
            if n == 0 {
                return Err("zero port");
            }
            let default_port = (scheme == "https" && n == 443) || (scheme == "http" && n == 80);
            if default_port { None } else { Some(n) }
        }
    };
    let is_loopback = matches!(host_raw.as_str(), "127.0.0.1" | "[::1]" | "localhost");
    if scheme == "http" && !is_loopback {
        return Err("http only allowed on loopback");
    }
    let origin = match port {
        Some(p) => format!("{scheme}://{host_raw}:{p}"),
        None => format!("{scheme}://{host_raw}"),
    };
    Ok((origin, host_raw))
}

pub fn apply(
    plan: &MigratePlan,
    consent: &MigrateConsent,
    proof: &MigrateProof<'_>,
) -> Result<MigrateReport, MigrateError> {
    for rw in &plan.rewrites {
        if let PlannedRewriteKind::HttpBridge { host, headers, .. } = &rw.kind {
            for h in headers {
                if !host_allowed_for_header(&h.value, &h.name, host) {
                    return Err(MigrateError::DisallowedHost {
                        server: rw.key(),
                        header: h.name.clone(),
                        host: host.clone(),
                    });
                }
            }
        }
    }

    if plan.rewrites.is_empty() {
        return Ok(build_empty_report(plan));
    }

    let passphrase = proof
        .passphrase
        .as_ref()
        .map(secret_copy)
        .ok_or(MigrateError::MissingPassphrase)?;

    let claude_cli = if plan
        .rewrites
        .iter()
        .any(|r| r.config_path == proof.loc.claude_json())
    {
        Some(claude::resolve_claude_cli(&proof.path_env)?)
    } else {
        None
    };

    let (mut state_file, mut state) =
        StateFile::open(&proof.data_dir).map_err(|r| MigrateError::Io {
            path: proof.data_dir.join("agents/state.json"),
            message: r.message,
        })?;

    let now = SystemTime::now();
    let mut file_order: Vec<PathBuf> = Vec::new();
    let mut file_snapshots: BTreeMap<PathBuf, FileSnapshot> = BTreeMap::new();

    for rw in &plan.rewrites {
        if !file_snapshots.contains_key(&rw.config_path) {
            let snap = preflight_config_file(
                &rw.config_path,
                &rw.agent,
                &state,
                now,
                proof.enforce_min_age,
            )?;
            file_order.push(rw.config_path.clone());
            file_snapshots.insert(rw.config_path.clone(), snap);
        }
    }

    let mut client = (proof.connect)().map_err(MigrateError::Client)?;

    let mut imported_by_server: BTreeMap<String, BTreeMap<String, ImportedSecretSummary>> =
        BTreeMap::new();
    let mut imported_list: Vec<ImportedSecretSummary> = Vec::new();

    for rw in &plan.rewrites {
        let srv_key = rw.key();
        let secrets_to_import: Vec<&PlannedSecret> = match &rw.kind {
            PlannedRewriteKind::Stdio { secrets, .. } => secrets.iter().collect(),
            PlannedRewriteKind::HttpBridge {
                headers,
                env_secrets,
                ..
            } => headers.iter().chain(env_secrets.iter()).collect(),
        };
        let label = format!(
            "mcp-{}-{}",
            update::sanitize_segment(&rw.agent),
            update::sanitize_segment(&rw.server)
        );
        let file_display = rw.config_path.display().to_string();

        let entries: Vec<ImportEntry> = secrets_to_import
            .iter()
            .enumerate()
            .map(|(idx, s)| ImportEntry {
                scope: ImportScope::Machine(MachineScope {
                    source: MachineSource::McpConfig,
                    label: label.clone(),
                }),
                file: file_display.clone(),
                line: u32::try_from(idx + 1).unwrap_or(1),
                profile: None,
                name: import_env_name(&s.name),
                value: WireSecret::new(secret_copy(&s.value)),
            })
            .collect();

        let import_params = ImportParams {
            projects: Vec::new(),
            entries,
            claims: proof.claims.clone(),
        };
        let planned_import = client
            .import_plan(&import_params)
            .map_err(|e| MigrateError::Client(Failure::from(e)))?;

        let entries_commit: Vec<ImportEntry> = secrets_to_import
            .iter()
            .enumerate()
            .map(|(idx, s)| ImportEntry {
                scope: ImportScope::Machine(MachineScope {
                    source: MachineSource::McpConfig,
                    label: label.clone(),
                }),
                file: file_display.clone(),
                line: u32::try_from(idx + 1).unwrap_or(1),
                profile: None,
                name: import_env_name(&s.name),
                value: WireSecret::new(secret_copy(&s.value)),
            })
            .collect();
        let committed_import = client
            .import_commit(&ImportCommitParams {
                import: ImportParams {
                    projects: Vec::new(),
                    entries: entries_commit,
                    claims: proof.claims.clone(),
                },
                digest: planned_import.digest,
            })
            .map_err(|e| MigrateError::Client(Failure::from(e)))?;

        let mut srv_map = BTreeMap::new();
        for (idx, s) in secrets_to_import.iter().enumerate() {
            let summary = if let Some(entry_view) = committed_import.entries.get(idx)
                && let Some(item_idx) = entry_view.item
                && let Some(item_view) = committed_import.items.get(item_idx as usize)
            {
                ImportedSecretSummary {
                    server: srv_key.clone(),
                    name: s.name.clone(),
                    slug: item_view.slug.clone(),
                    reference: item_view.reference.clone(),
                    classification: item_view.classification,
                }
            } else {
                let added = client
                    .items_add(&AddParams {
                        slug: None,
                        provider: None,
                        field: None,
                        account: Some(label.clone()),
                        env_hint: Some(import_env_name(&s.name)),
                        allow_short: true,
                        value: WireSecret::new(secret_copy(&s.value)),
                        claims: proof.claims.clone(),
                    })
                    .map_err(|e| MigrateError::Client(Failure::from(e)))?;
                ImportedSecretSummary {
                    server: srv_key.clone(),
                    name: s.name.clone(),
                    slug: added.item.slug.clone(),
                    reference: added.item.slug,
                    classification: added.item.classification,
                }
            };
            srv_map.insert(s.name.clone(), summary.clone());
            imported_list.push(summary);
        }
        imported_by_server.insert(srv_key, srv_map);
    }

    let envcloak_cmd = proof.envcloak_bin.to_string_lossy().into_owned();
    let effective_path = if !proof.path_env.is_empty() {
        Some(proof.path_env.to_string_lossy().into_owned())
    } else {
        std::env::var("PATH").ok()
    };

    let mut migrated_summaries: Vec<MigratedServerSummary> = Vec::new();
    let mut receipts: Vec<LaunchReceiptView> = Vec::new();

    for rw in &plan.rewrites {
        let srv_key = rw.key();
        let managed_dir = rw.managed_dir(&proof.data_dir);
        let manifest_path = rw.manifest_path(&proof.data_dir);
        let srv_imports =
            imported_by_server
                .get(&srv_key)
                .ok_or_else(|| MigrateError::ServerNotFound {
                    agent: rw.agent.clone(),
                    server: rw.server.clone(),
                })?;

        write_managed_manifest(&managed_dir, &manifest_path, rw, srv_imports)?;

        let (server_decl, standing_all_test) = match &rw.kind {
            PlannedRewriteKind::Stdio {
                argv,
                cwd,
                non_secret_env,
                secrets,
            } => {
                let resolved_argv =
                    resolve_stdio_argv(&proof.path_env, &proof.project_dir, argv, cwd.as_deref());
                let resolved_cwd =
                    resolve_stdio_cwd(&proof.project_dir, cwd.as_deref(), &managed_dir);
                let decl = ManagedServerDecl::Stdio {
                    launch: LaunchDeclParams {
                        argv: resolved_argv,
                        cwd: resolved_cwd,
                        env: non_secret_env.clone(),
                        path_env: effective_path.clone(),
                    },
                };
                let all_test = !secrets.is_empty()
                    && secrets.iter().all(|s| {
                        srv_imports
                            .get(&s.name)
                            .is_some_and(|imp| imp.classification == ClassificationView::Test)
                    });
                (decl, all_test)
            }
            PlannedRewriteKind::HttpBridge {
                origin, headers, ..
            } => {
                let header_names: Vec<String> = headers.iter().map(|h| h.name.clone()).collect();
                let decl = ManagedServerDecl::Bridge {
                    origin: origin.clone(),
                    header_names,
                };
                (decl, false)
            }
        };

        refuse_key_shaped_server(&server_decl).map_err(MigrateError::Client)?;

        let reg_params = ManagedRegisterParams {
            name: srv_key.clone(),
            manifest: manifest_path.to_string_lossy().into_owned(),
            server: server_decl,
            passphrase: WireSecret::new(secret_copy(&passphrase)),
            claims: proof.claims.clone(),
        };
        let registered =
            client_register(|| (proof.connect)(), &reg_params).map_err(MigrateError::Client)?;

        if let Some(launch_id) = &registered.launch {
            write_launch_id_file(&managed_dir, launch_id)?;
        }

        let rewritten_args = match &rw.kind {
            PlannedRewriteKind::Stdio { .. } => {
                let launch_id = registered
                    .launch
                    .clone()
                    .unwrap_or_else(|| registered.id.clone());
                vec![
                    "mcp-bridge".to_string(),
                    "--stdio".to_string(),
                    "--launch".to_string(),
                    launch_id,
                ]
            }
            PlannedRewriteKind::HttpBridge { url, headers, .. } => {
                let mut args = vec![
                    "mcp-bridge".to_string(),
                    "--manifest".to_string(),
                    manifest_path.to_string_lossy().into_owned(),
                    "--url".to_string(),
                    url.clone(),
                ];
                for h in headers {
                    if let Some(imp) = srv_imports.get(&h.name) {
                        args.push("--header".to_string());
                        args.push(format!("{}={}", h.name, imp.reference));
                    }
                }
                args
            }
        };

        let is_bound = registered.receipt.strength.as_deref() == Some("bound")
            && registered.receipt.class.as_deref() == Some("native");
        let standing_eligible = is_bound && standing_all_test;
        let codex_startup_timeout_set =
            rw.agent == "codex" && consent.startup_timeout && rw.codex_needs_startup_timeout;

        receipts.push(registered.receipt.clone());
        migrated_summaries.push(MigratedServerSummary {
            agent: rw.agent.clone(),
            server: rw.server.clone(),
            config_path: rw.config_path.clone(),
            manifest_path,
            transport: rw.transport_name().to_string(),
            launch_id: registered.launch,
            policy_id: registered.id,
            rewritten_command: envcloak_cmd.clone(),
            rewritten_args,
            codex_startup_timeout_set,
            standing_eligible,
            receipt: registered.receipt,
        });
    }

    let backup_plan_files: Vec<BackupPlanFile> = file_order
        .iter()
        .map(|p| {
            let snap = &file_snapshots[p];
            BackupPlanFile {
                path: p.to_string_lossy().into_owned(),
                size: snap.bytes.len() as u64,
                mode: snap.stamp.mode & 0o7777,
            }
        })
        .collect();

    let begun = client
        .backup_v2_begin(&BackupBeginParams {
            purpose: "migrate".to_string(),
            files: backup_plan_files,
            claims: proof.claims.clone(),
        })
        .map_err(|e| MigrateError::Client(Failure::from(e)))?;

    let chunk_size = usize::try_from(begun.chunk_size)
        .ok()
        .filter(|s| *s > 0)
        .unwrap_or(envcloak_core::file_backup_v2::CHUNK_V2);

    for (file_idx, path) in file_order.iter().enumerate() {
        let snap = &file_snapshots[path];
        let mut chunks: Vec<&[u8]> = snap.bytes.chunks(chunk_size).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        let file_u32 = u32::try_from(file_idx).unwrap_or(0);
        for (chunk_idx, chunk) in chunks.iter().enumerate() {
            let chunk_u32 = u32::try_from(chunk_idx).unwrap_or(0);
            client
                .backup_v2_put(
                    &begun.id,
                    file_u32,
                    chunk_u32,
                    SecretBytes::copy_from(chunk),
                )
                .map_err(|e| MigrateError::Client(Failure::from(e)))?;
        }
    }

    client
        .backup_v2_commit(&begun.id)
        .map_err(|e| MigrateError::Client(Failure::from(e)))?;

    let mut reg = MigrationRegistry::open(&proof.data_dir)?;
    let mut policy_ids = Vec::new();
    let mut server_keys = Vec::new();
    for s in &migrated_summaries {
        let key = format!("{}/{}", s.agent, s.server);
        policy_ids.push(s.policy_id.clone());
        server_keys.push(key.clone());
        reg.servers.insert(
            key,
            MigratedServerRecord {
                agent: s.agent.clone(),
                server: s.server.clone(),
                launch_id: s.launch_id.clone(),
                policy_id: s.policy_id.clone(),
                manifest: s.manifest_path.clone(),
                config_path: s.config_path.clone(),
            },
        );
    }
    reg.backups.insert(
        begun.id.clone(),
        BackupMigrationRecord {
            backup_id: begun.id.clone(),
            policy_ids,
            server_keys,
            files: file_order.clone(),
        },
    );
    reg.save(&proof.data_dir)?;

    pause_point("migrate_mcp_backed_up");

    let mut touched_mcp_json = false;
    for (file_idx, path) in file_order.iter().enumerate() {
        let snap = &file_snapshots[path];
        let servers_for_file: Vec<&MigratedServerSummary> = migrated_summaries
            .iter()
            .filter(|s| &s.config_path == path)
            .collect();

        let (after_bytes, new_stamp) = if path == proof.loc.claude_json() {
            let claude_bin = claude_cli
                .as_deref()
                .ok_or_else(|| MigrateError::MissingTool {
                    tool: "claude".to_string(),
                    detail: "claude CLI missing".to_string(),
                })?;
            let rewrites: Vec<(String, Value)> = servers_for_file
                .iter()
                .map(|s| {
                    (
                        s.server.clone(),
                        claude::build_entry_value(&s.rewritten_command, &s.rewritten_args),
                    )
                })
                .collect();
            let _ =
                claude::apply_claude_user_scope(proof.loc, &proof.path_env, claude_bin, &rewrites)?;
            let (reread_bytes, post_stamp) = read_plain(&snap.root, &snap.rel, MAX_HOST_STATE)
                .map_err(|_| MigrateError::Io {
                    path: path.clone(),
                    message: "failed to re-read ~/.claude.json after `claude mcp` update"
                        .to_string(),
                })?;
            verify_structural_reread(path, &reread_bytes)?;
            (reread_bytes, post_stamp)
        } else {
            let source_str =
                std::str::from_utf8(&snap.bytes).map_err(|e| MigrateError::InvalidConfig {
                    path: path.clone(),
                    reason: e.to_string(),
                })?;
            let rewritten_text = rewrite_file_contents(path, source_str, &servers_for_file)?;
            let post_bytes = rewritten_text.into_bytes();
            let post_stamp = replace_atomically(&snap.root, &snap.rel, &post_bytes, &snap.stamp)
                .map_err(|_| MigrateError::Changed { path: path.clone() })?;
            let (reread_bytes, _) = read_plain(&snap.root, &snap.rel, MAX_FILE.max(MAX_DOTENV))
                .map_err(|_| MigrateError::Changed { path: path.clone() })?;
            verify_structural_reread(path, &reread_bytes)?;
            (post_bytes, post_stamp)
        };

        let digest: [u8; 32] = Sha256::digest(&after_bytes).into();
        let file_u32 = u32::try_from(file_idx).unwrap_or(0);
        client
            .backup_v2_record_result(&begun.id, file_u32, &digest)
            .map_err(|e| MigrateError::Client(Failure::from(e)))?;

        let k = crate::writer::key(path);
        let s = Stamp::from(new_stamp);
        state.written.insert(k.clone(), s);
        if let Some(rec) = state.files.get_mut(&k) {
            rec.stamp = Some(s);
            rec.post_sha256 = sha256_hex(&after_bytes);
        }
        if path.file_name() == Some(OsStr::new(".mcp.json")) {
            touched_mcp_json = true;
        }
    }

    state_file.save(&state).map_err(|r| MigrateError::Io {
        path: proof.data_dir.join("agents/state.json"),
        message: r.message,
    })?;

    let mut reprobe_agents = Vec::new();
    if touched_mcp_json {
        update::invalidate_shared_mcp_cache(&proof.data_dir);
        reprobe_agents.push("claude-code".to_string());
        reprobe_agents.push("copilot".to_string());
    }

    let claude_backups = proof.loc.claude_dir().join("backups");
    let claude_backups_note =
        if claude_backups.exists() || file_order.iter().any(|p| p == proof.loc.claude_json()) {
            Some(format!(
                "Claude Code keeps pre-migration copies in {}; run `envcloak scrub` to inspect and \
             remove plaintext copies there.",
                claude_backups.display()
            ))
        } else {
            None
        };

    let mut next_steps = vec![
        "When an agent starts a migrated MCP server, run `envcloak pending` to see waiting \
         requests and their IDs, then `envcloak approve <id>` to release its bound secrets."
            .to_string(),
    ];
    for s in &migrated_summaries {
        if s.standing_eligible {
            next_steps.push(format!(
                "`{}/{}` is `bound` and binds only `test`-classified items: once a request appears \
                 in `envcloak pending`, you may approve it with `envcloak approve <id> --standing`.",
                s.agent, s.server
            ));
        }
    }
    if let Some(note) = &claude_backups_note {
        next_steps.push(note.clone());
    }

    Ok(MigrateReport {
        committed: true,
        backup_id: Some(begun.id),
        servers: migrated_summaries,
        receipts,
        imported_items: imported_list,
        manual_items: plan.manual_items.clone(),
        unavailable_opt_ins: plan.unavailable_opt_ins.clone(),
        claude_backups_note,
        reprobe_agents,
        next_steps,
    })
}

fn build_empty_report(plan: &MigratePlan) -> MigrateReport {
    let claude_backups_note = plan.claude_backups_dir.as_ref().map(|d| {
        format!(
            "Claude Code keeps copies in {}; run `envcloak scrub` to inspect and remove \
             plaintext copies there.",
            d.display()
        )
    });
    MigrateReport {
        committed: false,
        backup_id: None,
        servers: Vec::new(),
        receipts: Vec::new(),
        imported_items: Vec::new(),
        manual_items: plan.manual_items.clone(),
        unavailable_opt_ins: plan.unavailable_opt_ins.clone(),
        claude_backups_note,
        reprobe_agents: Vec::new(),
        next_steps: Vec::new(),
    }
}

struct FileSnapshot {
    root: envcloak_scan::ScanRoot,
    rel: PathBuf,
    bytes: Vec<u8>,
    stamp: FileStamp,
}

fn preflight_config_file(
    path: &Path,
    agent: &str,
    state: &State,
    now: SystemTime,
    enforce_min_age: bool,
) -> Result<FileSnapshot, MigrateError> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(MigrateError::Io {
            path: path.to_path_buf(),
            message: "invalid file path".to_string(),
        });
    };
    let root = open_root(parent).map_err(|e| MigrateError::Io {
        path: parent.to_path_buf(),
        message: e.to_string(),
    })?;
    let limit = if path.file_name() == Some(OsStr::new(".claude.json")) {
        MAX_HOST_STATE
    } else {
        MAX_FILE.max(MAX_DOTENV)
    };
    let rel = PathBuf::from(name);
    let (bytes, stamp) = read_plain(&root, &rel, limit).map_err(|e| match e.kind {
        ScanErrorKind::Changed => MigrateError::Changed {
            path: path.to_path_buf(),
        },
        _ => MigrateError::Io {
            path: path.to_path_buf(),
            message: e.kind.message().to_string(),
        },
    })?;

    if stamp.nlink > 1 {
        return Err(MigrateError::HardLinked {
            path: path.to_path_buf(),
        });
    }

    let open_fd =
        envcloak_sys::open_beneath(root.dir(), name).map_err(|_| MigrateError::Changed {
            path: path.to_path_buf(),
        })?;
    match envcloak_sys::open_elsewhere(&open_fd) {
        InUse::Yes => {
            return Err(MigrateError::OpenElsewhere {
                path: path.to_path_buf(),
            });
        }
        InUse::Unmatched => {
            return Err(MigrateError::Changed {
                path: path.to_path_buf(),
            });
        }
        InUse::No | InUse::Unknown => {}
    }

    if enforce_min_age
        && !is_self_written(state, path, &stamp)
        && stamp.age_at(now).is_none_or(|a| a < MIN_AGE.as_secs())
    {
        return Err(MigrateError::RecentlyChanged {
            path: path.to_path_buf(),
            agent: agent.to_string(),
        });
    }

    Ok(FileSnapshot {
        root,
        rel,
        bytes,
        stamp,
    })
}

pub fn is_self_written(state: &State, path: &Path, stamp: &FileStamp) -> bool {
    let k = crate::writer::key(path);
    let s = Stamp::from(*stamp);
    state.files.get(&k).is_some_and(|r| r.stamp == Some(s)) || state.written.get(&k) == Some(&s)
}

fn write_managed_manifest(
    managed_dir: &Path,
    manifest_path: &Path,
    rw: &PlannedServerMigration,
    imports: &BTreeMap<String, ImportedSecretSummary>,
) -> Result<(), MigrateError> {
    if let Some(parent) = managed_dir.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| MigrateError::Io {
                path: parent.to_path_buf(),
                message: e.to_string(),
            })?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(managed_dir)
        .map_err(|e| MigrateError::Io {
            path: managed_dir.to_path_buf(),
            message: e.to_string(),
        })?;
    let _ = fs::set_permissions(managed_dir, fs::Permissions::from_mode(0o700));

    let proj_name = format!(
        "mcp-{}-{}",
        update::sanitize_segment(&rw.agent),
        update::sanitize_segment(&rw.server)
    );
    let mut content = format!(
        "[project]\nname = {}\n\n[env]\n",
        serde_json::to_string(&proj_name).unwrap_or_default()
    );
    match &rw.kind {
        PlannedRewriteKind::Stdio { secrets, .. } => {
            for s in secrets {
                if let Some(imp) = imports.get(&s.name) {
                    content.push_str(&format!(
                        "{} = {}\n",
                        format_toml_key(&s.name),
                        serde_json::to_string(&imp.reference).unwrap_or_default()
                    ));
                }
            }
        }
        PlannedRewriteKind::HttpBridge {
            origin,
            headers,
            env_secrets,
            ..
        } => {
            for h in headers {
                if let Some(imp) = imports.get(&h.name)
                    && let Some(binding_name) = bridge_binding_name(&h.name, origin)
                {
                    content.push_str(&format!(
                        "{} = {}\n",
                        format_toml_key(&binding_name),
                        serde_json::to_string(&imp.reference).unwrap_or_default()
                    ));
                }
            }
            if !env_secrets.is_empty() {
                content.push_str("\n[env.extra]\n");
                for s in env_secrets {
                    if let Some(imp) = imports.get(&s.name) {
                        content.push_str(&format!(
                            "{} = {}\n",
                            format_toml_key(&s.name),
                            serde_json::to_string(&imp.reference).unwrap_or_default()
                        ));
                    }
                }
            }
        }
    }

    write_mode_0600(manifest_path, content.as_bytes())
}

fn import_env_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    let mut candidate = if trimmed.is_empty() {
        "MCP_SECRET".to_string()
    } else if trimmed.as_bytes()[0].is_ascii_digit() {
        format!("MCP_{trimmed}")
    } else {
        trimmed.to_string()
    };
    const SECRET_WORDS: [&str; 21] = [
        "KEY",
        "KEYS",
        "APIKEY",
        "TOKEN",
        "TOKENS",
        "SECRET",
        "SECRETS",
        "PASSWORD",
        "PASSWORDS",
        "PASSWD",
        "PASS",
        "PWD",
        "PASSPHRASE",
        "CREDENTIAL",
        "CREDENTIALS",
        "CREDS",
        "PRIVATE",
        "SALT",
        "SIGNATURE",
        "SESSION",
        "DSN",
    ];
    let has_word = candidate
        .split('_')
        .any(|w| SECRET_WORDS.iter().any(|s| s.eq_ignore_ascii_case(w)));
    if !has_word {
        candidate.push_str("_SECRET");
    }
    candidate
}

fn write_launch_id_file(managed_dir: &Path, launch_id: &str) -> Result<(), MigrateError> {
    let p = managed_dir.join("launch_id");
    write_mode_0600(&p, format!("{launch_id}\n").as_bytes())
}

fn write_mode_0600(path: &Path, bytes: &[u8]) -> Result<(), MigrateError> {
    let tmp = path.with_extension("tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| MigrateError::Io {
            path: tmp.clone(),
            message: e.to_string(),
        })?;
    f.write_all(bytes).map_err(|e| MigrateError::Io {
        path: tmp.clone(),
        message: e.to_string(),
    })?;
    f.sync_all().map_err(|e| MigrateError::Io {
        path: tmp.clone(),
        message: e.to_string(),
    })?;
    drop(f);
    fs::rename(&tmp, path).map_err(|e| MigrateError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    })
}

fn format_toml_key(k: &str) -> String {
    if !k.is_empty()
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        k.to_string()
    } else {
        serde_json::to_string(k).unwrap_or_else(|_| format!("\"{k}\""))
    }
}

fn resolve_stdio_argv(
    path_env: &OsStr,
    project_dir: &Path,
    argv: &[String],
    cwd: Option<&str>,
) -> Vec<String> {
    let Some((first, rest)) = argv.split_first() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(argv.len());
    if Path::new(first).is_absolute() {
        out.push(first.clone());
    } else if !path_env.is_empty()
        && let Some(found) = find_on_path(first, path_env)
    {
        out.push(found.to_string_lossy().into_owned());
    } else if let Some(sys_path) = std::env::var_os("PATH")
        && let Some(found) = find_on_path(first, &sys_path)
    {
        out.push(found.to_string_lossy().into_owned());
    } else {
        out.push(first.clone());
    }

    let base_dir = cwd
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| project_dir.to_path_buf());

    for arg in rest {
        if !arg.starts_with('-') && !Path::new(arg).is_absolute() {
            let candidate = base_dir.join(arg);
            if candidate.exists() {
                out.push(candidate.to_string_lossy().into_owned());
                continue;
            }
        }
        out.push(arg.clone());
    }
    out
}

fn resolve_stdio_cwd(project_dir: &Path, cwd: Option<&str>, managed_dir: &Path) -> Option<String> {
    match cwd {
        Some(c) if Path::new(c).is_absolute() => Some(c.to_string()),
        Some(c) => Some(project_dir.join(c).to_string_lossy().into_owned()),
        None => Some(managed_dir.to_string_lossy().into_owned()),
    }
}

fn rewrite_file_contents(
    path: &Path,
    source: &str,
    servers: &[&MigratedServerSummary],
) -> Result<String, MigrateError> {
    let Some(first) = servers.first() else {
        return Ok(source.to_string());
    };
    if path.extension() == Some(OsStr::new("toml")) || first.agent == "codex" {
        let codex_rewrites: Vec<codex::CodexServerRewrite> = servers
            .iter()
            .map(|s| codex::CodexServerRewrite {
                server: s.server.clone(),
                command: s.rewritten_command.clone(),
                args: s.rewritten_args.clone(),
                set_startup_timeout: s.codex_startup_timeout_set,
            })
            .collect();
        return codex::rewrite_codex_toml(path, source, &codex_rewrites);
    }

    let json_rewrites: Vec<(String, Value)> = servers
        .iter()
        .map(|s| {
            let entry = if first.agent == "opencode" {
                opencode::build_entry_value(&s.rewritten_command, &s.rewritten_args)
            } else {
                claude::build_entry_value(&s.rewritten_command, &s.rewritten_args)
            };
            (s.server.clone(), entry)
        })
        .collect();

    if path.file_name() == Some(OsStr::new(".mcp.json")) {
        return claude::rewrite_mcp_json(source, &json_rewrites);
    }

    match first.agent.as_str() {
        "cursor" => cursor::rewrite_cursor_json(path, source, &json_rewrites),
        "gemini" => gemini::rewrite_gemini_json(path, source, &json_rewrites),
        "copilot" => copilot::rewrite_copilot_json(path, source, &json_rewrites),
        "kimi" => kimi::rewrite_kimi_json(path, source, &json_rewrites),
        "opencode" => opencode::rewrite_opencode_json(path, source, &json_rewrites),
        _ => cursor::rewrite_cursor_json(path, source, &json_rewrites),
    }
}

fn verify_structural_reread(path: &Path, bytes: &[u8]) -> Result<(), MigrateError> {
    if path.extension() == Some(OsStr::new("toml")) {
        let s = std::str::from_utf8(bytes).map_err(|e| MigrateError::InvalidConfig {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        s.parse::<toml_edit::DocumentMut>()
            .map_err(|e| MigrateError::InvalidConfig {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;
    } else {
        Doc::parse(bytes).map_err(|e| MigrateError::InvalidConfig {
            path: path.to_path_buf(),
            reason: e.message().to_string(),
        })?;
    }
    Ok(())
}
