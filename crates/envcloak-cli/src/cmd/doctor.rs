//! CLI-owned scan and metadata-only report (SPEC section 6.5, gate 36).
use envcloak_agents::locations::Locations;
use envcloak_client::claims::claims;
use envcloak_client::connect::connect;
use envcloak_client::doctor_report::DoctorReport;
use envcloak_client::fail::{FAILURE, Failure, refuse_if_traced, usage};
use envcloak_ipc::proto::{
    CandidateForm, ExposedItem, MarkExposedParams, ScanCandidate, ScanMatchParams, ScanPurpose,
    ScanSource,
};
use envcloak_ipc::view::ExposureSourceView;
use envcloak_ipc::{Client, WireSecret};
use envcloak_scan::candidates::{
    Budget, Candidate, Candidates, Disposition, Encoding, Form, Occurrence, ScanReport, Source,
};
use envcloak_scan::source::{ConfigFormat, ConfigSource, SourceKind};
use envcloak_scan::{
    EntryKind, FileKind, MAX_DOTENV, WalkOptions, open_root, parse_dotenv, read_capped, walk_dotenv,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "envcloak doctor [--json] [--path <path>]... [--git-history]";
struct Options {
    json: bool,
    paths: Vec<PathBuf>,
    git: bool,
}
fn options(args: &[&str]) -> Result<Options, ()> {
    let mut o = Options {
        json: false,
        paths: Vec::new(),
        git: false,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "--json" if !o.json => o.json = true,
            "--git-history" if !o.git => o.git = true,
            "--path" if o.paths.len() < 64 => {
                let p = it
                    .next()
                    .filter(|p| !p.is_empty() && !p.starts_with("--"))
                    .ok_or(())?;
                o.paths.push(PathBuf::from(p));
            }
            _ => return Err(()),
        }
    }
    Ok(o)
}
pub fn run(args: &[&str]) -> ExitCode {
    let o = match options(args) {
        Ok(o) => o,
        Err(()) => return usage(USAGE),
    };
    match execute(&o) {
        Ok(report) => {
            if o.json {
                println!("{}", report.json());
            } else {
                print!("{}", report.human());
            }
            if report.complete() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(FAILURE)
            }
        }
        Err(e) => e.report(FAILURE),
    }
}
struct Scan {
    candidates: Candidates,
    report: DoctorReport,
    budget: Budget,
    kinds: BTreeMap<PathBuf, BTreeSet<ExposureSourceView>>,
    sources: Vec<ConfigSource>,
    covered: HashSet<PathBuf>,
}
impl Scan {
    fn issue(&mut self, path: &Path, reason: &'static str) {
        if reason == "candidate_budget" {
            self.report.fail("limited");
        }
        self.report.note(path, reason, true);
    }
    fn kind(&mut self, path: &Path, kind: ExposureSourceView) {
        self.kinds
            .entry(normal_path(path))
            .or_default()
            .insert(kind);
    }
    fn absorb(&mut self, mut r: ScanReport, kind: ExposureSourceView) {
        self.budget.bytes = self.budget.bytes.saturating_sub(r.bytes);
        self.budget.files = self.budget.files.saturating_sub(r.files as usize);
        for f in r.findings.drain(..) {
            self.covered.insert(normal_path(&f.source.path));
            if f.disposition == Disposition::Template {
                continue;
            }
            if let Some(value) = f.value {
                if value.is_empty() {
                    continue;
                }
                if !self
                    .kinds
                    .keys()
                    .any(|p| normal_path(&f.source.path).starts_with(p))
                {
                    self.kind(&f.source.path, kind);
                }
                if !self.candidates.insert(Candidate {
                    id: 0,
                    value,
                    form: Form::Raw,
                    occurrence: Occurrence {
                        source: f.source,
                        range: f.range,
                        encoding: Encoding::Raw,
                        stamp: f.stamp,
                        rewritable: false,
                    },
                }) {
                    self.report.fail("limited");
                    break;
                }
            }
        }
        for i in r.issues {
            self.issue(&i.source.path, i.reason);
        }
        for i in r.notes {
            self.report.note(&i.source.path, i.reason, false);
        }
    }
}
fn normal_path(p: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    for base in ["/tmp", "/var", "/etc"] {
        if let Ok(rest) = p.strip_prefix(base) {
            return Path::new("/private").join(&base[1..]).join(rest);
        }
    }
    p.to_path_buf()
}
fn descriptor(path: PathBuf, format: ConfigFormat, source_kind: SourceKind) -> ConfigSource {
    ConfigSource {
        path,
        format,
        source_kind,
        label: "doctor path".into(),
        names: None,
    }
}
fn execute(o: &Options) -> Result<DoctorReport, Failure> {
    // Must precede catalog inspection and every plaintext read (L-10).
    refuse_if_traced()?;
    let locations =
        Locations::from_env().map_err(|_| Failure::new("io", "an absolute HOME is required"))?;
    let mut client = connect()?;
    super::require_unlocked(&mut client)?;
    drop(client);
    let cwd = std::env::current_dir()
        .map_err(|_| Failure::new("io", "cannot open the current directory"))?;
    let budget = Budget {
        bytes: 2 << 30,
        ..Budget::for_counts()
    };
    let mut scan = Scan {
        candidates: Candidates::counted(budget)
            .map_err(|_| Failure::new("io", "cannot prepare a scan"))?,
        report: DoctorReport::default(),
        budget,
        kinds: BTreeMap::new(),
        sources: Vec::new(),
        covered: HashSet::new(),
    };
    let mut roots = vec![locations.home().to_path_buf(), cwd.clone()];
    let mut transcripts = locations.transcript_sources();
    let mut configs = locations.config_sources();
    for path in &o.paths {
        let path = if path.is_absolute() {
            path.clone()
        } else {
            cwd.join(path)
        };
        if path
            .file_name()
            .is_some_and(|n| matches!(envcloak_scan::dotenv_kind(n), Some(Ok(FileKind::Template))))
        {
            scan.covered.insert(normal_path(&path));
        }
        if std::fs::symlink_metadata(&path).is_err() {
            scan.issue(&path, "not_found");
        }
        // All content opens remain in the scanner, including special files.
        if path.is_dir() {
            roots.push(path.clone());
        }
        transcripts.push(descriptor(
            path,
            ConfigFormat::Mixed,
            SourceKind::Transcript,
        ));
    }
    roots = roots.iter().map(|p| normal_path(p)).collect();
    roots.sort();
    roots.dedup();
    let explicit: Vec<_> = o
        .paths
        .iter()
        .map(|p| {
            normal_path(&if p.is_absolute() {
                p.clone()
            } else {
                cwd.join(p)
            })
        })
        .collect();
    configs.retain(|s| source_admitted(&s.path, &explicit, &mut scan.report));
    transcripts.retain(|s| source_admitted(&s.path, &explicit, &mut scan.report));
    if source_admitted(locations.home(), &explicit, &mut scan.report) {
        if let Ok(root) = open_root(locations.home()) {
            match envcloak_scan::profile::scan_profiles(&root) {
                Ok(r) => scan.absorb(r, ExposureSourceView::ShellProfile),
                Err(e) => scan.issue(locations.home(), e.kind.token()),
            }
        } else {
            scan.issue(locations.home(), "unreadable");
        }
    }
    let mut seen = HashSet::new();
    for path in &roots {
        if !source_admitted(path, &explicit, &mut scan.report) {
            continue;
        }
        configs.extend(
            Locations::project_config_sources(path)
                .into_iter()
                .filter(|s| source_admitted(&s.path, &explicit, &mut scan.report)),
        );
        let root = match open_root(path) {
            Ok(r) => r,
            Err(_) => {
                scan.issue(path, "unreadable");
                continue;
            }
        };
        let allowance = scan.budget.files;
        let walk = walk_dotenv(
            &root,
            &WalkOptions {
                recursive: true,
                max_files: allowance.saturating_add(1),
                skip_dirs: WalkOptions::default()
                    .skip_dirs
                    .into_iter()
                    .chain(["Dropbox".into(), "OneDrive".into()])
                    .collect(),
                ..WalkOptions::default()
            },
        );
        for (index, file) in walk.enumerate() {
            if index >= allowance {
                scan.issue(root.path(), "file_budget");
                break;
            }
            scan.budget.files = scan.budget.files.saturating_sub(1);
            let file = match file {
                Ok(f) => f,
                Err(e) => {
                    scan.issue(&path.join(e.rel), e.kind.token());
                    continue;
                }
            };
            scan.covered.insert(normal_path(&path.join(&file.rel)));
            if file.kind == FileKind::Template || !seen.insert(normal_path(&path.join(&file.rel))) {
                continue;
            }
            let p = root.path().join(&file.rel);
            if file.hard_linked {
                scan.issue(&p, "hard_link");
            }
            match read_capped(&root, &file.rel, MAX_DOTENV.min(scan.budget.bytes as usize)) {
                Ok((bytes, stamp)) => {
                    scan.budget.bytes = scan.budget.bytes.saturating_sub(bytes.len() as u64);
                    match parse_dotenv(&bytes) {
                        Ok(entries) => {
                            for entry in entries {
                                if entry.kind == EntryKind::Plain {
                                    let value = entry.value;
                                    if value.is_empty() {
                                        continue;
                                    }
                                    scan.kind(&p, ExposureSourceView::EnvFile);
                                    if !scan.candidates.insert(Candidate {
                                        id: 0,
                                        value,
                                        form: Form::Raw,
                                        occurrence: Occurrence {
                                            source: Source {
                                                path: p.clone(),
                                                object: None,
                                            },
                                            range: 0..0,
                                            encoding: Encoding::Raw,
                                            stamp: Some(stamp),
                                            rewritable: false,
                                        },
                                    }) {
                                        scan.report.fail("limited");
                                        break;
                                    }
                                }
                            }
                        }
                        Err(_) => scan.issue(&p, "invalid_text"),
                    }
                }
                Err(e) => scan.issue(&p, e.kind.token()),
            }
        }
        if o.git && git_present(&root, &mut scan.report) {
            match envcloak_scan::git::scan_git_history(&root, scan.budget, &mut |c| {
                scan.candidates.insert(c)
            }) {
                Ok(r) => {
                    scan.budget.bytes = scan.budget.bytes.saturating_sub(r.bytes);
                    for i in r.issues {
                        scan.issue(&i.source.path, i.reason);
                    }
                }
                Err(e) => scan.issue(path, e.kind.token()),
            }
        } else if !o.git {
            scan.report.note(path, "git_history_opt_in", false);
        }
    }
    // A single config discovery preserves include/omission policy and its budget.
    match envcloak_scan::agent_config::scan_config_sources_with_budget(&configs, scan.budget) {
        Ok(r) => scan.absorb(r, ExposureSourceView::AgentConfig),
        Err(e) => scan.issue(locations.home(), e.kind.token()),
    }
    transcripts.extend(
        configs
            .iter()
            .filter(|s| {
                matches!(
                    s.source_kind,
                    SourceKind::Credentials | SourceKind::Database
                )
            })
            .cloned(),
    );
    scan.sources.extend(configs);
    scan.sources.extend(transcripts.clone());
    // These files were already parsed, or are name-only templates. A broad
    // explicit directory must neither count them twice nor read template values.
    transcripts.extend(
        scan.covered
            .iter()
            .map(|p| descriptor(p.clone(), ConfigFormat::Raw, SourceKind::Credentials)),
    );
    eprintln!("doctor: scanning transcript stores");
    match envcloak_scan::transcript::scan_transcript_sources(&transcripts, scan.budget, &mut |c| {
        scan.candidates.insert(c)
    }) {
        Ok(mut r) => {
            r.notes
                .retain(|i| !scan.covered.contains(&normal_path(&i.source.path)));
            scan.absorb(r, ExposureSourceView::Transcript);
        }
        Err(e) => scan.issue(locations.home(), e.kind.token()),
    }
    for path in &o.paths {
        let p = if path.is_absolute() {
            path.clone()
        } else {
            cwd.join(path)
        };
        if std::fs::symlink_metadata(&p).is_err() {
            scan.issue(&p, "not_found");
        }
    }
    scan.report.note(&cwd, "gemini_may_autoload_dotenv", false);
    if scan.candidates.limited() {
        scan.report.fail("limited");
    }
    compare(scan, &mut connect()?)
}
fn compare(mut scan: Scan, client: &mut Client) -> Result<DoctorReport, Failure> {
    let entries = scan.candidates.into_entries();
    let mut pending = entries.into_iter().peekable();
    let mut exposed: BTreeMap<String, ExposedItem> = BTreeMap::new();
    let mut found: BTreeMap<(String, String, PathBuf), u64> = BTreeMap::new();
    while pending.peek().is_some() {
        // Bound value bytes as well as count. Base64 and field overhead then
        // fit below the 1 MiB frame cap without paying for one RPC per few tokens.
        let mut candidates = Vec::new();
        let mut counts = BTreeMap::new();
        let mut bytes = 0;
        while candidates.len() < envcloak_ipc::proto::MAX_SCAN_CANDIDATES {
            let Some(next) = pending.peek() else { break };
            if next.value.len() > 4096 {
                scan.report.fail("candidate_too_large");
                pending.next();
                continue;
            }
            if bytes + next.value.len() > 256 * 1024 {
                break;
            }
            let Some(entry) = pending.next() else { break };
            bytes += entry.value.len();
            let id = entry.id as u32;
            counts.insert(id, entry.counts);
            candidates.push(ScanCandidate {
                id,
                value: WireSecret::new(entry.value),
                form: match entry.form {
                    Form::Raw => CandidateForm::Raw,
                    Form::UrlPassword => CandidateForm::UrlPassword,
                    Form::DsnPassword => CandidateForm::DsnPassword,
                    Form::ConnPassword => CandidateForm::ConnPassword,
                },
            });
        }
        if candidates.is_empty() {
            continue;
        }
        let answer = match client.scan_match(&ScanMatchParams {
            candidates,
            source_kind: ScanSource::Mixed,
            purpose: ScanPurpose::Doctor,
            claims: claims(),
        }) {
            Ok(a) => a,
            Err(e) => {
                scan.report.fail(if e.token() == "too_many_checks" {
                    "limited"
                } else {
                    e.token()
                });
                break;
            }
        };
        for m in answer.matches {
            let Some(places) = counts.get(&m.id) else {
                scan.report.fail("invalid_response");
                continue;
            };
            for (source, count) in places {
                *found
                    .entry((m.item.clone(), m.slug.clone(), source.path.clone()))
                    .or_default() += count;
                let kinds = exposure_kinds(source, &scan.kinds, &scan.sources);
                let e = exposed
                    .entry(m.item.clone())
                    .or_insert_with(|| ExposedItem {
                        item: m.item.clone(),
                        sources: Vec::new(),
                        count: 0,
                    });
                e.count = e.count.saturating_add(*count);
                e.sources.extend(kinds);
                e.sources.sort();
                e.sources.dedup();
            }
        }
        for p in answer.patterns {
            if let Some(places) = counts.get(&p.id) {
                for (source, count) in places {
                    scan.report.unknown(&p.provider, &source.path, *count);
                }
            } else {
                scan.report.fail("invalid_response");
            }
        }
        if answer.limited {
            scan.report.fail("limited");
            break;
        }
    }
    let mut marks = exposed.into_values().peekable();
    if marks.peek().is_some() {
        envcloak_scan::pause_point("doctor_before_mark");
    }
    while marks.peek().is_some() {
        let params = MarkExposedParams {
            items: marks.by_ref().take(256).collect(),
            claims: claims(),
        };
        match client.items_mark_exposed(&params) {
            Ok(v) if v.missing == 0 => (),
            Ok(_) => scan.report.fail("items_changed"),
            Err(e) => {
                scan.report.fail(e.token());
                break;
            }
        }
    }
    // Re-read display metadata after comparisons and marks, which can span
    // a long run. Never cache a provider or slug from before those operations.
    let items = match client.items_list(false) {
        Ok(v) => v.items,
        Err(e) => {
            scan.report.fail(e.token());
            Vec::new()
        }
    };
    for ((id, slug, path), count) in found {
        let current = items.iter().find(|i| i.id == id);
        scan.report.item(
            current.map_or(slug.as_str(), |i| i.slug.as_str()),
            current.and_then(|i| i.provider.as_deref()),
            &path,
            count,
        );
    }
    Ok(scan.report)
}
fn exposure_kinds(
    source: &Source,
    kinds: &BTreeMap<PathBuf, BTreeSet<ExposureSourceView>>,
    sources: &[ConfigSource],
) -> BTreeSet<ExposureSourceView> {
    if source.object.is_some() {
        return [ExposureSourceView::GitHistory].into();
    }
    let path = normal_path(&source.path);
    let mut out: BTreeSet<_> = kinds
        .iter()
        .filter(|(p, _)| path.starts_with(p))
        .flat_map(|(_, ks)| ks.iter().copied())
        .collect();
    for source in sources {
        let root = normal_path(&source.path);
        let applies = match &source.names {
            Some(name) => {
                path.parent() == Some(root.as_path())
                    && path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.contains(name))
            }
            None => path.starts_with(root),
        };
        if applies {
            out.insert(match source.source_kind {
                SourceKind::HostBackup => ExposureSourceView::ConfigBackup,
                SourceKind::McpConfig | SourceKind::ProviderConfig => {
                    ExposureSourceView::AgentConfig
                }
                _ => ExposureSourceView::Transcript,
            });
        }
    }
    if path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some("CloudStorage" | "Mobile Documents" | "Dropbox" | "OneDrive")
        )
    }) {
        out.insert(ExposureSourceView::SyncedFolder);
    }
    if out.is_empty() {
        out.insert(ExposureSourceView::Transcript);
    }
    out
}

fn source_admitted(path: &Path, explicit: &[PathBuf], report: &mut DoctorReport) -> bool {
    let path = normal_path(path);
    if explicit.iter().any(|p| path.starts_with(p)) {
        return true;
    }
    if path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some("CloudStorage" | "Mobile Documents" | "Dropbox" | "OneDrive")
        )
    }) {
        report.note(&path, "synced_folder_opt_in", false);
        return false;
    }
    let parent = if path.is_dir() {
        path.as_path()
    } else {
        path.parent().unwrap_or(&path)
    };
    if open_root(parent).is_ok_and(|r| r.volume() == envcloak_sys::Volume::Network) {
        report.note(&path, "network_volume_opt_in", false);
        return false;
    }
    true
}

fn git_present(root: &envcloak_scan::ScanRoot, report: &mut DoctorReport) -> bool {
    use std::ffi::OsStr;
    for name in [".git", "HEAD"] {
        match envcloak_sys::kind_beneath(root.dir(), OsStr::new(name)) {
            Ok(_) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => {
                report.note(root.path(), "unreadable", true);
                return false;
            }
        }
    }
    report.note(root.path(), "not_git_repository", false);
    false
}
