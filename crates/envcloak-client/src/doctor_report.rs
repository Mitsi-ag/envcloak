//! Doctor's metadata-only report. No input bytes, ranges or object ids belong here.
use crate::render::{HIDDEN, json_text, looks_like_value, registry, shown};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

#[derive(Debug, Default, Serialize)]
pub struct DoctorReport {
    items: Vec<Item>,
    unknown: Vec<Unknown>,
    not_scanned: Vec<NotScanned>,
    incomplete: Option<&'static str>,
}
#[derive(Debug, Serialize)]
struct Place {
    display_path: String,
    count: u64,
    #[serde(skip)]
    report_path: String,
}
#[derive(Debug, Serialize)]
struct Item {
    slug: String,
    places: Vec<Place>,
    rotate_url: Option<String>,
    #[serde(skip)]
    raw_slug: String,
}
#[derive(Debug, Serialize)]
struct Unknown {
    provider: String,
    places: Vec<Place>,
}
#[derive(Debug, Serialize)]
struct NotScanned {
    display_path: String,
    reason: &'static str,
}

fn name(s: &str) -> String {
    if looks_like_value(s) {
        HIDDEN.into()
    } else {
        shown(s)
    }
}
/// Mask a single string for `FirstRunReport` when shaped like a value, while
/// keeping raw Unicode scalars intact so `json_text` escapes control/bidi
/// scalars once as JSON `\uXXXX` and Swift's `DaemonText` decodes raw scalars.
pub fn report_name(s: &str) -> String {
    if looks_like_value(s) {
        HIDDEN.into()
    } else {
        s.to_owned()
    }
}
/// Mask each path component for `FirstRunReport` when shaped like a value or
/// non-UTF-8, without pre-converting Unicode scalars to literal `\u{...}` text.
pub fn report_path(path: &Path) -> String {
    let Some(text) = path.to_str() else {
        return HIDDEN.into();
    };
    text.split('/')
        .map(report_name)
        .collect::<Vec<_>>()
        .join("/")
}
/// Mask each component before escaping controls, including non-UTF-8 names.
pub fn display_path(path: &Path) -> String {
    let Some(text) = path.to_str() else {
        return HIDDEN.into();
    };
    text.split('/').map(name).collect::<Vec<_>>().join("/")
}
fn place(places: &mut Vec<Place>, path: &Path, count: u64) {
    let rpath = report_path(path);
    let path = display_path(path);
    if let Some(p) = places.iter_mut().find(|p| p.display_path == path) {
        p.count = p.count.saturating_add(count);
    } else {
        places.push(Place {
            display_path: path,
            count,
            report_path: rpath,
        });
    }
    places.sort_by(|a, b| a.display_path.cmp(&b.display_path));
}
impl DoctorReport {
    pub fn complete(&self) -> bool {
        self.incomplete.is_none()
    }
    pub fn fail(&mut self, reason: &'static str) {
        self.incomplete.get_or_insert(reason);
    }
    pub fn note(&mut self, path: &Path, reason: &'static str, incomplete: bool) {
        let path = display_path(path);
        if !self
            .not_scanned
            .iter()
            .any(|n| n.display_path == path && n.reason == reason)
        {
            self.not_scanned.push(NotScanned {
                display_path: path,
                reason,
            });
            self.not_scanned
                .sort_by(|a, b| (&a.display_path, a.reason).cmp(&(&b.display_path, b.reason)));
        }
        if incomplete {
            self.fail(reason);
        }
    }
    pub fn item(&mut self, slug: &str, provider: Option<&str>, path: &Path, count: u64) {
        let raw_slug = report_name(slug);
        let slug = name(slug);
        let index = self
            .items
            .iter()
            .position(|i| i.slug == slug)
            .unwrap_or_else(|| {
                // Only the embedded registry supplies URLs, never an item's mutable links.
                let rotate_url = provider.and_then(|p| registry()?.get(p)?.links.keys_page.clone());
                self.items.push(Item {
                    slug,
                    places: Vec::new(),
                    rotate_url,
                    raw_slug,
                });
                self.items.len() - 1
            });
        place(&mut self.items[index].places, path, count);
        self.items.sort_by(|a, b| a.slug.cmp(&b.slug));
    }
    pub fn unknown(&mut self, provider: &str, path: &Path, count: u64) {
        let provider = name(provider);
        let index = self
            .unknown
            .iter()
            .position(|i| i.provider == provider)
            .unwrap_or_else(|| {
                self.unknown.push(Unknown {
                    provider,
                    places: Vec::new(),
                });
                self.unknown.len() - 1
            });
        place(&mut self.unknown[index].places, path, count);
        self.unknown.sort_by(|a, b| a.provider.cmp(&b.provider));
    }
    pub fn json(&self) -> String {
        json_text(self)
    }
    pub fn human(&self) -> String {
        let mut text = String::new();
        for item in &self.items {
            let _ = writeln!(text, "item {}", item.slug);
            for p in &item.places {
                let _ = writeln!(text, "  path {} count {}", p.display_path, p.count);
            }
            if let Some(url) = &item.rotate_url {
                let _ = writeln!(text, "rotate {url}");
            } else {
                let _ = writeln!(text, "rotate at provider key page");
            }
        }
        for item in &self.unknown {
            let _ = writeln!(text, "unknown {}", item.provider);
            for p in &item.places {
                let _ = writeln!(text, "  path {} count {}", p.display_path, p.count);
            }
        }
        // Rotation precedes scrub, including a pattern-only finding.
        let urls: BTreeMap<_, _> = self
            .unknown
            .iter()
            .filter_map(|u| {
                Some((
                    u.provider.as_str(),
                    registry()?.get(&u.provider)?.links.keys_page.as_deref()?,
                ))
            })
            .collect();
        for url in urls.values() {
            let _ = writeln!(text, "rotate {url}");
        }
        if !self.items.is_empty() || !self.unknown.is_empty() {
            text.push_str("envcloak scrub: encrypted backup before rewriting\n");
        }
        for n in &self.not_scanned {
            let _ = writeln!(text, "not_scanned {} {}", n.display_path, n.reason);
        }
        if let Some(reason) = self.incomplete {
            let _ = writeln!(text, "doctor: incomplete ({reason})");
        } else {
            text.push_str("doctor: complete\n");
        }
        text
    }
}

/// File name of the first-run scan report inside `<data>/reports/`.
pub const FIRST_RUN_REPORT_FILE: &str = "first-run.json";
/// Schema version of [`FirstRunReport`].
pub const FIRST_RUN_REPORT_VERSION: u64 = 1;
/// Maximum byte length of `<data>/reports/first-run.json` (1 MiB, matching Swift `Frame.limit`).
pub const FIRST_RUN_REPORT_MAX_BYTES: u64 = 1_048_576;

/// Value-free first-run scan and doctor report written to
/// `<data>/reports/first-run.json` with mode 0600 (D3-13, R-M3-38, M3-J4).
/// Every field is a count, a sanitized slug, a sanitized display path, an
/// account identifier, or an enum token; no field can hold a secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstRunReport {
    pub version: u64,
    pub keys_found: u64,
    pub projects: u64,
    pub already_leaked: u64,
    pub plaintext_files: u64,
    pub providers: Vec<FirstRunProvider>,
    pub accounts: Vec<FirstRunAccount>,
    pub leaked: Vec<FirstRunLeakedItem>,
    pub plaintext_projects: Vec<FirstRunProjectPlaintext>,
}

impl Default for FirstRunReport {
    fn default() -> Self {
        Self {
            version: FIRST_RUN_REPORT_VERSION,
            keys_found: 0,
            projects: 0,
            already_leaked: 0,
            plaintext_files: 0,
            providers: Vec::new(),
            accounts: Vec::new(),
            leaked: Vec::new(),
            plaintext_projects: Vec::new(),
        }
    }
}

/// Provider count and live-key count in [`FirstRunReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstRunProvider {
    pub provider: String,
    pub total_count: u64,
    pub live_count: u64,
}

impl FirstRunProvider {
    pub fn new(provider: &str, total_count: u64, live_count: u64) -> Self {
        let p = if provider.trim().is_empty() {
            "generic".to_owned()
        } else {
            report_name(provider)
        };
        Self {
            provider: p,
            total_count,
            live_count,
        }
    }
}

/// Account identifier and key count in [`FirstRunReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstRunAccount {
    pub account: String,
    pub count: u64,
}

impl FirstRunAccount {
    /// Returns `None` when `account` is empty or shaped like a secret value.
    pub fn new(account: &str, count: u64) -> Option<Self> {
        let trimmed = account.trim();
        if trimmed.is_empty() || looks_like_value(trimmed) {
            return None;
        }
        Some(Self {
            account: trimmed.to_owned(),
            count,
        })
    }
}

/// A place where an exposed key was found in [`FirstRunLeakedItem`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstRunLeakedPlace {
    pub display_path: String,
    pub count: u64,
}

impl FirstRunLeakedPlace {
    pub fn new(path: &Path, count: u64) -> Self {
        Self {
            display_path: report_path(path),
            count,
        }
    }
}

fn is_valid_exposure_source_token(s: &str) -> bool {
    matches!(
        s,
        "transcript"
            | "git_history"
            | "config_backup"
            | "synced_folder"
            | "shell_profile"
            | "agent_config"
            | "env_file"
    )
}

/// An exposed key entry in [`FirstRunReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstRunLeakedItem {
    pub slug: String,
    pub provider: Option<String>,
    pub rotate_url: Option<String>,
    pub sources: Vec<String>,
    pub places: Vec<FirstRunLeakedPlace>,
}

impl FirstRunLeakedItem {
    pub fn new(
        slug: &str,
        provider: Option<&str>,
        sources: Vec<String>,
        places: Vec<FirstRunLeakedPlace>,
    ) -> Self {
        let clean_provider = provider.filter(|p| !p.trim().is_empty()).map(report_name);
        let rotate_url = clean_provider
            .as_deref()
            .and_then(|p| registry()?.get(p)?.links.keys_page.clone());
        let mut clean_sources: Vec<String> = sources
            .into_iter()
            .filter(|s| is_valid_exposure_source_token(s.as_str()))
            .collect();
        clean_sources.sort();
        clean_sources.dedup();
        let clean_places: Vec<FirstRunLeakedPlace> = places
            .into_iter()
            .map(|p| FirstRunLeakedPlace::new(Path::new(&p.display_path), p.count))
            .collect();
        Self {
            slug: report_name(slug),
            provider: clean_provider,
            rotate_url,
            sources: clean_sources,
            places: clean_places,
        }
    }
}

/// Plaintext env files grouped by project in [`FirstRunReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstRunProjectPlaintext {
    pub project_dir: String,
    pub files: Vec<String>,
}

impl FirstRunProjectPlaintext {
    pub fn new(project_dir: &Path, files: Vec<String>) -> Self {
        let mut clean_files: Vec<String> = files
            .into_iter()
            .filter(|f| !f.trim().is_empty())
            .map(|f| report_path(Path::new(&f)))
            .collect();
        clean_files.sort();
        clean_files.dedup();
        Self {
            project_dir: report_path(project_dir),
            files: clean_files,
        }
    }
}

fn exposure_source_token(s: envcloak_ipc::view::ExposureSourceView) -> &'static str {
    use envcloak_ipc::view::ExposureSourceView;
    match s {
        ExposureSourceView::Transcript => "transcript",
        ExposureSourceView::GitHistory => "git_history",
        ExposureSourceView::ConfigBackup => "config_backup",
        ExposureSourceView::SyncedFolder => "synced_folder",
        ExposureSourceView::ShellProfile => "shell_profile",
        ExposureSourceView::AgentConfig => "agent_config",
        ExposureSourceView::EnvFile => "env_file",
    }
}

impl DoctorReport {
    /// Builds the leaked items list for [`FirstRunReport`] by combining this
    /// doctor run's findings with the vault's item metadata.
    pub fn to_first_run_leaked(
        &self,
        vault_items: &[envcloak_ipc::view::ItemView],
        prior: Option<&FirstRunReport>,
    ) -> Vec<FirstRunLeakedItem> {
        let mut out: Vec<FirstRunLeakedItem> = Vec::new();
        for item in &self.items {
            let meta = vault_items
                .iter()
                .find(|v| name(&v.slug) == item.slug || report_name(&v.slug) == item.raw_slug);
            let slug_source = meta.map_or(item.raw_slug.as_str(), |v| v.slug.as_str());
            let provider = meta.and_then(|v| v.provider.as_deref());
            let sources: Vec<String> = meta
                .and_then(|v| v.exposed.as_ref())
                .map(|e| {
                    e.sources
                        .iter()
                        .copied()
                        .map(|s| exposure_source_token(s).to_owned())
                        .collect()
                })
                .unwrap_or_else(|| vec!["transcript".to_owned()]);
            let places = item
                .places
                .iter()
                .map(|p| FirstRunLeakedPlace::new(Path::new(&p.report_path), p.count))
                .collect();
            let mut leaked = FirstRunLeakedItem::new(slug_source, provider, sources, places);
            if leaked.rotate_url.is_none() {
                leaked.rotate_url.clone_from(&item.rotate_url);
            }
            out.push(leaked);
        }
        for v in vault_items {
            let Some(exp) = &v.exposed else { continue };
            let slug = report_name(&v.slug);
            if out.iter().any(|i| i.slug == slug) {
                continue;
            }
            let prior_places = prior
                .and_then(|p| p.leaked.iter().find(|i| i.slug == slug))
                .map(|i| i.places.clone())
                .unwrap_or_default();
            let sources = exp
                .sources
                .iter()
                .copied()
                .map(|s| exposure_source_token(s).to_owned())
                .collect();
            out.push(FirstRunLeakedItem::new(
                &v.slug,
                v.provider.as_deref(),
                sources,
                prior_places,
            ));
        }
        out.sort_by(|a, b| a.slug.cmp(&b.slug));
        out
    }
}

impl FirstRunReport {
    /// Summarizes provider counts and accounts from `vault_items`.
    pub fn summarize_vault_items(
        vault_items: &[envcloak_ipc::view::ItemView],
    ) -> (u64, Vec<FirstRunProvider>, Vec<FirstRunAccount>) {
        use envcloak_ipc::view::{ClassificationView, ItemClassView};
        let secrets: Vec<&envcloak_ipc::view::ItemView> = vault_items
            .iter()
            .filter(|i| i.class == ItemClassView::Secret)
            .collect();
        let mut by_provider: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        let mut by_account: BTreeMap<String, u64> = BTreeMap::new();
        for item in &secrets {
            let p = item
                .provider
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .map(report_name)
                .unwrap_or_else(|| "generic".to_owned());
            let entry = by_provider.entry(p).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(1);
            if item.classification == ClassificationView::Live {
                entry.1 = entry.1.saturating_add(1);
            }
            if let Some(acct) = &item.account {
                let raw = acct
                    .email
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| acct.label.as_deref().filter(|s| !s.trim().is_empty()));
                if let Some(raw) = raw {
                    if let Some(clean) = FirstRunAccount::new(raw, 1) {
                        *by_account.entry(clean.account).or_insert(0) += 1;
                    }
                }
            }
        }
        let providers = by_provider
            .into_iter()
            .map(|(provider, (total_count, live_count))| FirstRunProvider {
                provider,
                total_count,
                live_count,
            })
            .collect();
        let accounts = by_account
            .into_iter()
            .map(|(account, count)| FirstRunAccount { account, count })
            .collect();
        (secrets.len() as u64, providers, accounts)
    }

    /// Re-sanitizes all strings and re-derives `rotate_url` from the embedded
    /// provider registry when loading a prior report from disk.
    pub fn sanitized(self) -> Self {
        let mut by_provider: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for p in self.providers {
            let clean = FirstRunProvider::new(&p.provider, p.total_count, p.live_count);
            let entry = by_provider.entry(clean.provider).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(clean.total_count);
            entry.1 = entry.1.saturating_add(clean.live_count);
        }
        let providers: Vec<FirstRunProvider> = by_provider
            .into_iter()
            .map(|(provider, (total_count, live_count))| FirstRunProvider {
                provider,
                total_count,
                live_count,
            })
            .collect();
        let mut by_account: BTreeMap<String, u64> = BTreeMap::new();
        for a in self.accounts {
            if let Some(clean) = FirstRunAccount::new(&a.account, a.count) {
                let entry = by_account.entry(clean.account).or_insert(0);
                *entry = entry.saturating_add(clean.count);
            }
        }
        let accounts: Vec<FirstRunAccount> = by_account
            .into_iter()
            .map(|(account, count)| FirstRunAccount { account, count })
            .collect();
        let mut leaked: Vec<FirstRunLeakedItem> = self
            .leaked
            .into_iter()
            .map(|l| FirstRunLeakedItem::new(&l.slug, l.provider.as_deref(), l.sources, l.places))
            .collect();
        leaked.sort_by(|a, b| a.slug.cmp(&b.slug));
        let mut plaintext_projects: Vec<FirstRunProjectPlaintext> = self
            .plaintext_projects
            .into_iter()
            .map(|p| FirstRunProjectPlaintext::new(Path::new(&p.project_dir), p.files))
            .collect();
        plaintext_projects.sort_by(|a, b| a.project_dir.cmp(&b.project_dir));
        let already_leaked = leaked.len() as u64;
        Self {
            version: FIRST_RUN_REPORT_VERSION,
            keys_found: self.keys_found,
            projects: self.projects.max(plaintext_projects.len() as u64),
            already_leaked,
            plaintext_files: self.plaintext_files,
            providers,
            accounts,
            leaked,
            plaintext_projects,
        }
    }

    /// Combines a `DoctorReport` and the current vault inventory with an
    /// optional prior `FirstRunReport` from `import --scan --report`.
    pub fn from_doctor(
        doctor: &DoctorReport,
        vault_items: &[envcloak_ipc::view::ItemView],
        prior: Option<&FirstRunReport>,
    ) -> Self {
        let (vault_keys, vault_providers, vault_accounts) =
            Self::summarize_vault_items(vault_items);
        let mut by_provider: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for vp in vault_providers {
            by_provider.insert(vp.provider, (vp.total_count, vp.live_count));
        }
        if let Some(p) = prior {
            for pp in &p.providers {
                let clean = FirstRunProvider::new(&pp.provider, pp.total_count, pp.live_count);
                let entry = by_provider.entry(clean.provider).or_insert((0, 0));
                entry.0 = entry.0.max(clean.total_count);
                entry.1 = entry.1.max(clean.live_count);
            }
        }
        let providers: Vec<FirstRunProvider> = by_provider
            .into_iter()
            .map(|(provider, (total_count, live_count))| FirstRunProvider {
                provider,
                total_count,
                live_count,
            })
            .collect();
        let provider_sum: u64 = providers.iter().map(|p| p.total_count).sum();
        let keys_found = vault_keys
            .max(prior.map_or(0, |p| p.keys_found))
            .max(provider_sum);
        let accounts = if !vault_accounts.is_empty() {
            vault_accounts
        } else {
            prior.map(|p| p.accounts.clone()).unwrap_or_default()
        };
        let leaked = doctor.to_first_run_leaked(vault_items, prior);
        let already_leaked = leaked.len() as u64;
        let plaintext_projects = prior
            .map(|p| p.plaintext_projects.clone())
            .unwrap_or_default();
        let projects = prior
            .map_or(0, |p| p.projects)
            .max(plaintext_projects.len() as u64);
        let plaintext_files = prior.map_or_else(
            || {
                plaintext_projects
                    .iter()
                    .map(|p| p.files.len() as u64)
                    .sum()
            },
            |p| p.plaintext_files,
        );
        Self {
            version: FIRST_RUN_REPORT_VERSION,
            keys_found,
            projects,
            already_leaked,
            plaintext_files,
            providers,
            accounts,
            leaked,
            plaintext_projects,
        }
    }

    pub fn json(&self) -> String {
        json_text(self)
    }
}

/// Reads `<data>/reports/first-run.json` for the current user when present and
/// owned by the effective uid with private permissions.
pub fn read_first_run_report() -> Option<FirstRunReport> {
    let paths = envcloak_core::vault::VaultPaths::for_user().ok()?;
    read_first_run_report_under(&paths.data_dir)
}

fn check_private_dir(dir: &Path) -> Option<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
        .ok()?;
    let m = file.metadata().ok()?;
    if !m.is_dir() || m.uid() != envcloak_sys::effective_uid() || (m.mode() & 0o077 != 0) {
        return None;
    }
    Some(file)
}

/// Reads `<data_dir>/reports/first-run.json` when present and private.
pub fn read_first_run_report_under(data_dir: &Path) -> Option<FirstRunReport> {
    use std::fs::OpenOptions;
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let _data_dir_handle = check_private_dir(data_dir)?;
    let reports_dir = data_dir.join("reports");
    let _reports_dir_handle = check_private_dir(&reports_dir)?;
    let path = reports_dir.join(FIRST_RUN_REPORT_FILE);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .ok()?;
    let m = file.metadata().ok()?;
    if !m.is_file()
        || m.uid() != envcloak_sys::effective_uid()
        || (m.mode() & 0o777 != 0o600)
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > FIRST_RUN_REPORT_MAX_BYTES
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(m.len() as usize);
    file.take(FIRST_RUN_REPORT_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.is_empty() || (bytes.len() as u64) > FIRST_RUN_REPORT_MAX_BYTES {
        return None;
    }
    let raw: FirstRunReport = serde_json::from_slice(&bytes).ok()?;
    if raw.version != FIRST_RUN_REPORT_VERSION {
        return None;
    }
    Some(raw.sanitized())
}

/// Writes `report` atomically to `<data>/reports/first-run.json` with mode
/// `0600` inside a `0700` `<data>/reports/` directory.
pub fn write_first_run_report(
    report: &FirstRunReport,
) -> Result<std::path::PathBuf, crate::fail::Failure> {
    let paths = envcloak_core::vault::VaultPaths::for_user()
        .map_err(|_| crate::fail::Failure::new("io", "could not resolve the data directory"))?;
    write_first_run_report_under(&paths.data_dir, report)
}

fn ensure_private_dir(dir: &Path) -> Result<std::fs::File, crate::fail::Failure> {
    use std::fs::{DirBuilder, OpenOptions, Permissions};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    match std::fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|_| {
                    crate::fail::Failure::new("io", "could not create the reports directory")
                })?;
        }
        Err(_) => {
            return Err(crate::fail::Failure::new(
                "io",
                "could not inspect the reports directory",
            ));
        }
    }
    let dir_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
        .map_err(|_| {
            crate::fail::Failure::new(
                "io",
                "the reports directory is not a private directory owned by this user",
            )
        })?;
    let m = dir_file
        .metadata()
        .map_err(|_| crate::fail::Failure::new("io", "could not inspect the reports directory"))?;
    if !m.is_dir() || m.uid() != envcloak_sys::effective_uid() || (m.mode() & 0o022 != 0) {
        return Err(crate::fail::Failure::new(
            "io",
            "the reports directory is not a private directory owned by this user",
        ));
    }
    if (m.mode() & 0o7777) != 0o700 {
        dir_file
            .set_permissions(Permissions::from_mode(0o700))
            .map_err(|_| {
                crate::fail::Failure::new(
                    "io",
                    "could not tighten permissions on the reports directory",
                )
            })?;
    }
    Ok(dir_file)
}

/// Writes `report` atomically to `<data_dir>/reports/first-run.json` with mode
/// `0600` inside a `0700` `<data_dir>/reports/` directory.
pub fn write_first_run_report_under(
    data_dir: &Path,
    report: &FirstRunReport,
) -> Result<std::path::PathBuf, crate::fail::Failure> {
    use std::fs::{OpenOptions, Permissions};
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    envcloak_sys::restrict_umask();
    let _data_dir_handle = ensure_private_dir(data_dir)?;
    let reports_dir = data_dir.join("reports");
    let reports_dir_handle = ensure_private_dir(&reports_dir)?;
    let dest = reports_dir.join(FIRST_RUN_REPORT_FILE);
    if std::fs::symlink_metadata(&dest).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(crate::fail::Failure::new(
            "io",
            "refusing to overwrite a symlink in the reports directory",
        ));
    }
    let tmp = reports_dir.join(format!(
        ".{FIRST_RUN_REPORT_FILE}.tmp-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp);
    let mut text = report.json();
    text.push('\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&tmp)
        .map_err(|_| {
            crate::fail::Failure::new("io", "could not create the temporary report file")
        })?;
    if let Err(e) = (|| -> Result<(), crate::fail::Failure> {
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(|_| {
                crate::fail::Failure::new("io", "could not set report file permissions")
            })?;
        file.write_all(text.as_bytes())
            .map_err(|_| crate::fail::Failure::new("io", "could not write the report file"))?;
        envcloak_sys::sync_file(&file)
            .map_err(|_| crate::fail::Failure::new("io", "could not flush the report file"))?;
        Ok(())
    })() {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(file);
    if std::fs::rename(&tmp, &dest).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(crate::fail::Failure::new(
            "io",
            "could not move the report file into place",
        ));
    }
    let _ = envcloak_sys::sync_file(&reports_dir_handle);
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn report_masks_hostile_metadata_and_keeps_only_the_schema() {
        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        let v = std::str::from_utf8(
            envcloak_testkit::by_label(&cs, envcloak_testkit::labels::OPENAI_API_KEY).value(),
        )
        .expect("fixture");
        let mut r = DoctorReport::default();
        r.item(v, Some("openai"), &Path::new("/tmp").join(v), 2);
        r.note(Path::new("/tmp/\u{202e}\n"), "unreadable", true);
        for s in [r.human(), r.json(), format!("{r:?}")] {
            envcloak_testkit::assert_no_canary(s.as_bytes(), &cs);
            assert!(!s.contains('\u{202e}'));
        }
        let j: serde_json::Value = serde_json::from_str(&r.json()).expect("json");
        assert_eq!(j["items"][0]["places"][0]["count"], 2);
        assert_eq!(j["items"][0].as_object().expect("item").len(), 3);
        assert_eq!(
            j["items"][0]["places"][0].as_object().expect("place").len(),
            2
        );
        assert!(!r.complete());
    }

    /// R-M3-38: every field in `FirstRunReport` and its nested structs is a
    /// count, a slug, a display path, an account identifier, or an enum token;
    /// no field can hold a value or preview.
    #[test]
    fn first_run_report_schema_allows_only_counts_slugs_paths_accounts_and_enums() {
        let src = include_str!("doctor_report.rs");
        let mut declared: Vec<(String, String, String)> = Vec::new();
        let mut current_struct: Option<String> = None;
        for line in src.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("pub struct FirstRun") {
                let name = rest
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or_default();
                current_struct = Some(format!("FirstRun{name}"));
                continue;
            }
            if let Some(struct_name) = &current_struct {
                if trimmed == "}" {
                    current_struct = None;
                    continue;
                }
                if let Some(field_decl) = trimmed.strip_prefix("pub ") {
                    if let Some((field_name, field_type)) = field_decl.split_once(':') {
                        let field_name = field_name.trim().to_owned();
                        let field_type = field_type.trim().trim_end_matches(',').trim().to_owned();
                        declared.push((struct_name.clone(), field_name, field_type));
                    }
                }
            }
        }
        let expected: Vec<(&str, &str, &str)> = vec![
            ("FirstRunReport", "version", "u64"),
            ("FirstRunReport", "keys_found", "u64"),
            ("FirstRunReport", "projects", "u64"),
            ("FirstRunReport", "already_leaked", "u64"),
            ("FirstRunReport", "plaintext_files", "u64"),
            ("FirstRunReport", "providers", "Vec<FirstRunProvider>"),
            ("FirstRunReport", "accounts", "Vec<FirstRunAccount>"),
            ("FirstRunReport", "leaked", "Vec<FirstRunLeakedItem>"),
            (
                "FirstRunReport",
                "plaintext_projects",
                "Vec<FirstRunProjectPlaintext>",
            ),
            ("FirstRunProvider", "provider", "String"),
            ("FirstRunProvider", "total_count", "u64"),
            ("FirstRunProvider", "live_count", "u64"),
            ("FirstRunAccount", "account", "String"),
            ("FirstRunAccount", "count", "u64"),
            ("FirstRunLeakedPlace", "display_path", "String"),
            ("FirstRunLeakedPlace", "count", "u64"),
            ("FirstRunLeakedItem", "slug", "String"),
            ("FirstRunLeakedItem", "provider", "Option<String>"),
            ("FirstRunLeakedItem", "rotate_url", "Option<String>"),
            ("FirstRunLeakedItem", "sources", "Vec<String>"),
            ("FirstRunLeakedItem", "places", "Vec<FirstRunLeakedPlace>"),
            ("FirstRunProjectPlaintext", "project_dir", "String"),
            ("FirstRunProjectPlaintext", "files", "Vec<String>"),
        ];
        let actual_refs: Vec<(&str, &str, &str)> = declared
            .iter()
            .map(|(s, f, t)| (s.as_str(), f.as_str(), t.as_str()))
            .collect();
        assert_eq!(
            actual_refs, expected,
            "FirstRunReport struct schema changed: no value or preview field is permitted"
        );

        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        let openai = std::str::from_utf8(
            envcloak_testkit::by_label(&cs, envcloak_testkit::labels::OPENAI_API_KEY).value(),
        )
        .expect("utf8");
        let stripe = std::str::from_utf8(
            envcloak_testkit::by_label(&cs, envcloak_testkit::labels::STRIPE_SECRET_KEY).value(),
        )
        .expect("utf8");
        // Positive control: raw canary is detected by the testkit sweep.
        assert!(
            !envcloak_testkit::find(openai.as_bytes(), &cs).is_empty(),
            "positive control must detect canary"
        );
        assert!(
            FirstRunAccount::new(openai, 1).is_none(),
            "value-shaped account must be rejected"
        );
        let valid_account =
            FirstRunAccount::new("billing@acme.example", 2).expect("valid email account");
        let report = FirstRunReport {
            version: FIRST_RUN_REPORT_VERSION,
            keys_found: 4,
            projects: 1,
            already_leaked: 1,
            plaintext_files: 1,
            providers: vec![FirstRunProvider::new("stripe", 4, 2)],
            accounts: vec![valid_account],
            leaked: vec![FirstRunLeakedItem::new(
                openai,
                Some("openai"),
                vec!["transcript".to_owned(), stripe.to_owned()],
                vec![FirstRunLeakedPlace::new(&Path::new("/tmp").join(openai), 3)],
            )],
            plaintext_projects: vec![FirstRunProjectPlaintext::new(
                &Path::new("/tmp/acme-web").join(stripe),
                vec![format!(".env.{openai}")],
            )],
        };
        let dir = tempfile::tempdir_in("/tmp").expect("tempdir");
        let written = write_first_run_report_under(dir.path(), &report).expect("write report");
        let file_mode = std::fs::symlink_metadata(&written)
            .expect("file meta")
            .permissions()
            .mode()
            & 0o777;
        let dir_mode = std::fs::symlink_metadata(written.parent().expect("parent"))
            .expect("dir meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "report file must be 0600");
        assert_eq!(dir_mode, 0o700, "reports dir must be 0700");

        let disk_bytes = std::fs::read(&written).expect("read report");
        envcloak_testkit::assert_no_canary(&disk_bytes, &cs);
        let decoded = read_first_run_report_under(dir.path()).expect("decode report");
        assert_eq!(decoded, report);
        assert_eq!(decoded.leaked[0].sources, vec!["transcript".to_owned()]);

        // Control and directional scalars are escaped as \uXXXX in disk JSON bytes
        // and decoded back as raw scalars without double-escaping.
        let hostile_report = FirstRunReport {
            version: FIRST_RUN_REPORT_VERSION,
            keys_found: 1,
            projects: 1,
            already_leaked: 1,
            plaintext_files: 1,
            providers: vec![FirstRunProvider::new("custom\u{202e}", 1, 0)],
            accounts: Vec::new(),
            leaked: vec![FirstRunLeakedItem::new(
                "stripe/acme\u{202e}\n",
                Some("stripe"),
                vec!["transcript".to_owned()],
                vec![FirstRunLeakedPlace::new(
                    Path::new("/tmp/claude\u{202e}.jsonl"),
                    1,
                )],
            )],
            plaintext_projects: vec![FirstRunProjectPlaintext::new(
                Path::new("/tmp/acme\u{202e}"),
                vec![".env".to_owned()],
            )],
        };
        let written_hostile =
            write_first_run_report_under(dir.path(), &hostile_report).expect("write hostile");
        let hostile_text = std::fs::read_to_string(&written_hostile).expect("read hostile");
        assert!(
            !hostile_text.contains('\u{202e}'),
            "raw directional scalar must not appear in on-disk JSON bytes"
        );
        let roundtrip = read_first_run_report_under(dir.path()).expect("read hostile");
        assert_eq!(roundtrip.leaked[0].slug, "stripe/acme\u{202e}\n");
        assert_eq!(
            roundtrip.plaintext_projects[0].project_dir,
            "/tmp/acme\u{202e}"
        );

        // Tampered rotate_url and value-shaped fields in prior file are sanitized on read;
        // invalid permissions, hard links, or version mismatch are rejected.
        let tampered_json = serde_json::json!({
            "version": 1,
            "keys_found": 5,
            "projects": 2,
            "already_leaked": 1,
            "plaintext_files": 1,
            "providers": [{"provider": "stripe", "total_count": 4, "live_count": 2}],
            "accounts": [{"account": openai, "count": 1}, {"account": "valid@acme.example", "count": 2}],
            "leaked": [{
                "slug": openai,
                "provider": "stripe",
                "rotate_url": "https://evil.example/phish",
                "sources": ["transcript", stripe],
                "places": [{"display_path": format!("/tmp/{openai}"), "count": 2}]
            }],
            "plaintext_projects": [{"project_dir": "/tmp/acme", "files": [".env"]}]
        });
        std::fs::write(
            &written_hostile,
            serde_json::to_vec(&tampered_json).expect("json"),
        )
        .expect("write tampered");
        std::fs::set_permissions(&written_hostile, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600");
        let sanitized_prior = read_first_run_report_under(dir.path()).expect("sanitized prior");
        assert_eq!(sanitized_prior.accounts.len(), 1);
        assert_eq!(sanitized_prior.accounts[0].account, "valid@acme.example");
        assert_eq!(sanitized_prior.leaked[0].slug, HIDDEN);
        assert_eq!(
            sanitized_prior.leaked[0].rotate_url.as_deref(),
            Some("https://dashboard.stripe.com/apikeys")
        );
        assert_eq!(
            sanitized_prior.leaked[0].sources,
            vec!["transcript".to_owned()]
        );

        // Merge with non-empty vault inventory preserves discovered prior counts/providers.
        let vault_item = envcloak_ipc::view::ItemView {
            id: "item_1".to_owned(),
            slug: "openai/main".to_owned(),
            class: envcloak_ipc::view::ItemClassView::Secret,
            title: "OpenAI".to_owned(),
            provider: Some("openai".to_owned()),
            classification: envcloak_ipc::view::ClassificationView::Live,
            env_hint: Some("OPENAI_API_KEY".to_owned()),
            allow_short: false,
            fields: Vec::new(),
            created_secs: 1,
            updated_secs: 1,
            rotated_secs: None,
            expires_secs: None,
            last_used_secs: None,
            account: None,
            detail: None,
            exposed: None,
        };
        let merged = FirstRunReport::from_doctor(
            &DoctorReport::default(),
            &[vault_item],
            Some(&sanitized_prior),
        );
        assert_eq!(merged.keys_found, 5);
        assert!(
            merged
                .providers
                .iter()
                .any(|p| p.provider == "openai" && p.total_count == 1)
        );
        assert!(
            merged
                .providers
                .iter()
                .any(|p| p.provider == "stripe" && p.total_count == 4)
        );

        // 0644 file or hard link must be rejected by read_first_run_report_under.
        std::fs::set_permissions(&written_hostile, std::fs::Permissions::from_mode(0o644))
            .expect("chmod 0644");
        assert!(
            read_first_run_report_under(dir.path()).is_none(),
            "0644 report must be rejected"
        );
        std::fs::set_permissions(&written_hostile, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600");
        let hardlink = written_hostile.with_file_name("hardlink.json");
        std::fs::hard_link(&written_hostile, &hardlink).expect("hard link");
        assert!(
            read_first_run_report_under(dir.path()).is_none(),
            "hard-linked report must be rejected"
        );
        std::fs::remove_file(&hardlink).expect("remove hardlink");
        assert!(read_first_run_report_under(dir.path()).is_some());
    }
}
