//! Machine-wide import orchestration. All comparisons use verified daemon IPC.
use super::*;
use envcloak_agents::locations::Locations;
use envcloak_client::doctor_report::display_path;
use envcloak_client::render::{Render, json_text, shown};
use envcloak_ipc::proto::{
    CandidateForm, MachineScope, MachineSource, ScanCandidate, ScanMatchParams, ScanPurpose,
    ScanSource,
};
use envcloak_scan::candidates::{
    Budget, Candidate, Candidates, Disposition, Encoding, Form, Found, Occurrence, ScanReport,
};
use envcloak_scan::first_run::{assignment_name, secret_copy};
use envcloak_scan::source::SourceKind;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashSet};

mod cleanup;

struct Group {
    root: ScanRoot,
    projects: Vec<Project>,
    skipped: Vec<SkippedPath>,
    sent: Sent,
    start: usize,
}
struct MachineEntry {
    found: Found,
    kind: MachineSource,
    sent: Option<usize>,
}
impl MachineEntry {
    fn name(&self) -> Option<String> {
        if self.kind == MachineSource::McpConfig {
            envcloak_scan::first_run::mcp_assignment_name(&self.found)
        } else {
            assignment_name(&self.found)
        }
    }
}
struct FirstRunReport {
    sources: BTreeMap<PathBuf, Value>,
    incomplete: BTreeSet<String>,
    backups: Vec<String>,
}
impl FirstRunReport {
    fn new() -> Self {
        Self {
            sources: BTreeMap::new(),
            incomplete: BTreeSet::new(),
            backups: Vec::new(),
        }
    }
    fn source(&mut self, path: &Path, kind: &str) -> &mut Value {
        self.sources.entry(path.to_path_buf()).or_insert_with(|| {
            json!({
                "kind":kind,"display_path":display_path(path),"found":0,"imported":0,"kept":[]
            })
        })
    }
    fn keep(&mut self, path: &Path, kind: &str, name: Option<&str>, reason: &str) {
        let kept = json!({"name":name.map(safe_name),"reason":reason});
        let source = self.source(path, kind);
        if let Some(entries) = source["kept"].as_array_mut() {
            if !entries.contains(&kept) {
                entries.push(kept);
            }
        }
    }
    fn fail(&mut self, path: &Path, kind: &str, reason: &str) {
        self.incomplete.insert(reason.to_owned());
        self.keep(path, kind, None, reason);
    }
}
fn safe_name(text: &str) -> String {
    if looks_like_value(text) {
        HIDDEN.into()
    } else {
        shown(text)
    }
}
fn kind(kind: MachineSource) -> &'static str {
    match kind {
        MachineSource::Profile => "profile",
        MachineSource::McpConfig => "mcp_config",
        MachineSource::Aws => "aws",
        MachineSource::Export => "export",
    }
}
fn normal_path(path: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    for alias in ["/tmp", "/var", "/etc"] {
        if let Ok(rest) = path.strip_prefix(alias) {
            return Path::new("/private").join(&alias[1..]).join(rest);
        }
    }
    path.to_path_buf()
}
fn synced(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str().to_str().is_some_and(|component| {
            ["CloudStorage", "Mobile Documents", "Dropbox", "OneDrive"]
                .iter()
                .any(|name| component.eq_ignore_ascii_case(name))
        })
    })
}
fn source_allowed(path: &Path, named: &[PathBuf]) -> bool {
    let path = normal_path(path);
    let parent = path.parent().and_then(|p| open_root(p).ok());
    let network = parent
        .as_ref()
        .is_some_and(|root| root.volume() == envcloak_sys::Volume::Network);
    // A case alias of an explicitly named directory is the same selection.
    // This metadata lookup grants no permission to follow child symlinks.
    let resolved = parent
        .as_ref()
        .and_then(|p| path.file_name().map(|name| p.path().join(name)))
        .unwrap_or_else(|| path.clone());
    if !synced(&path) && !synced(&resolved) && !network {
        return true;
    }
    named.iter().filter_map(|p| open_root(p).ok()).any(|root| {
        resolved.starts_with(root.path())
            && (synced(root.path()) || root.volume() == envcloak_sys::Volume::Network)
    })
}
fn check_budget(params: &ImportParams, machine: &[MachineEntry]) -> Result<(), Failure> {
    let retained: usize = params
        .entries
        .iter()
        .map(|e| e.value.as_secret().len())
        .sum::<usize>()
        + machine
            .iter()
            .filter_map(|m| m.found.value.as_ref())
            .map(SecretBytes::len)
            .sum::<usize>();
    if retained > 32 << 20 || params.entries.len() + machine.len() > 50_000 {
        Err(Failure::new(
            "limited",
            "the first-run retention budget was reached",
        ))
    } else {
        Ok(())
    }
}
fn absorb(
    part: ScanReport,
    kind_value: MachineSource,
    machine: &mut Vec<MachineEntry>,
    r: &mut FirstRunReport,
    seen: &mut HashSet<(PathBuf, u64, u64)>,
) {
    for note in part.notes {
        r.keep(&note.source.path, kind(kind_value), None, note.reason);
    }
    for leftover in part.leftovers {
        r.fail(&leftover.source.path, kind(kind_value), "leftover");
        r.keep(
            &leftover.source.path,
            kind(kind_value),
            None,
            leftover.inspection,
        );
    }
    for issue in part.issues {
        if issue.reason == "volume_opt_in" {
            r.keep(&issue.source.path, kind(kind_value), None, issue.reason);
        } else {
            r.fail(&issue.source.path, kind(kind_value), issue.reason);
        }
    }
    for f in part.findings {
        // An included dotenv is already represented by its project. Keep one
        // provenance and one cleanup owner for the physical file.
        if r.sources
            .get(&f.source.path)
            .is_some_and(|s| s["kind"] == "dotenv")
        {
            continue;
        }
        if !seen.insert((f.source.path.clone(), f.range.start, f.range.end)) {
            continue;
        }
        let source = r.source(&f.source.path, kind(kind_value));
        source["found"] = json!(source["found"].as_u64().unwrap_or(0) + 1);
        machine.push(MachineEntry {
            found: f,
            kind: kind_value,
            sent: None,
        });
    }
}

pub(super) fn run(options: &ImportArgs) -> Result<ExitCode, Failure> {
    envcloak_client::fail::refuse_if_traced()?;
    let locations = Locations::from_env()
        .map_err(|_| Failure::new("scan_root", "an absolute HOME is required"))?;
    let mut paths = options.dirs.clone();
    if options.machine {
        paths.push(locations.home().to_path_buf());
    }
    let mut r = FirstRunReport::new();
    let mut roots = Vec::new();
    let mut root_names = Vec::new();
    for path in paths {
        let root = open_root(&path)
            .map_err(|_| Failure::new("scan_root", "the scan directory could not be opened"))?;
        root_names.push((path.clone(), root.path().to_path_buf()));
        if roots
            .iter()
            .any(|x: &ScanRoot| x.identity() == root.identity())
        {
            continue;
        }
        if options.machine
            && path == locations.home()
            && !options.dirs.contains(&path)
            && (root.volume() == envcloak_sys::Volume::Network || synced(root.path()))
        {
            r.keep(root.path(), "root", None, "volume_opt_in");
            continue;
        }
        roots.push(root);
    }
    roots.sort_by(|a, b| a.path().cmp(b.path()));
    let mut configs = locations.config_sources();
    // Resolve only the explicitly opened root alias. Child paths still pass
    // through the scanner's no-follow walk.
    for source in &mut configs {
        if let Some(path) = root_names.iter().find_map(|(name, canonical)| {
            source
                .path
                .strip_prefix(name)
                .ok()
                .map(|rel| canonical.join(rel))
        }) {
            source.path = path;
        }
    }
    // Omission policy survives readable-source, root and volume selection.
    let omissions = configs
        .iter()
        .filter(|s| {
            matches!(
                s.source_kind,
                SourceKind::Credentials | SourceKind::Database
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    configs.retain(|s| {
        roots
            .iter()
            .any(|root| normal_path(&s.path).starts_with(root.path()))
            && matches!(s.source_kind, SourceKind::McpConfig)
    });
    let mut groups = Vec::new();
    let mut machine = Vec::new();
    let mut seen = HashSet::new();
    let mut project_paths = HashSet::new();
    let mut params = ImportParams {
        projects: Vec::new(),
        entries: Vec::new(),
        claims: claims(),
    };
    for root in roots {
        let (mut projects, skipped, directories) =
            scan_selected(&root, true, options.machine, &omissions);
        projects.retain(|p| project_paths.insert(dir_of(&root, &p.rel_dir)));
        for directory in directories {
            configs.extend(Locations::project_config_sources(&dir_of(
                &root, &directory,
            )));
        }
        for s in &skipped {
            if s.reason == "excluded_directory" {
                r.keep(&root.path().join(&s.path), "directory", None, &s.reason);
            } else {
                r.fail(&root.path().join(&s.path), "dotenv", &s.reason);
            }
        }
        let (mut part, sent) = import_params(&root, &projects, claims());
        let offset = params.projects.len() as u32;
        let start = params.entries.len();
        for e in &mut part.entries {
            if let ImportScope::Project(p) = &mut e.scope {
                *p += offset;
            }
        }
        params.projects.extend(part.projects);
        params.entries.extend(part.entries);
        for file in projects.iter().flat_map(|p| &p.files) {
            let path = root.path().join(&file.rel);
            match &file.parsed {
                Err(e) => r.fail(&path, "dotenv", e.kind().token()),
                Ok(entries) => {
                    r.source(&path, "dotenv")["found"] = json!(entries.len());
                    for e in entries {
                        if file.template || e.kind != EntryKind::Plain {
                            r.keep(
                                &path,
                                "dotenv",
                                Some(e.name.as_str()),
                                "template_or_reference",
                            );
                        }
                    }
                }
            }
        }
        match envcloak_scan::profile::scan_profiles_selected(&root, &|path| {
            source_allowed(path, &options.dirs)
                && !envcloak_scan::sources::omitted_path(&omissions, path)
        }) {
            Ok(mut part) => {
                for issue in &mut part.issues {
                    if envcloak_scan::sources::omitted_path(&omissions, &issue.source.path) {
                        issue.reason = "manual_credentials";
                    }
                }
                absorb(
                    part,
                    MachineSource::Profile,
                    &mut machine,
                    &mut r,
                    &mut seen,
                );
            }
            Err(e) => r.fail(root.path(), "profile", e.kind.token()),
        }
        absorb(
            envcloak_scan::aws::scan_aws(&root),
            MachineSource::Aws,
            &mut machine,
            &mut r,
            &mut seen,
        );
        check_budget(&params, &machine)?;
        groups.push(Group {
            root,
            projects,
            skipped,
            sent,
            start,
        });
    }
    configs.retain(|source| {
        if source_allowed(&source.path, &options.dirs) {
            true
        } else {
            r.keep(&source.path, "mcp_config", None, "volume_opt_in");
            false
        }
    });
    configs.extend(omissions);
    let part = envcloak_scan::agent_config::scan_config_sources_selected(
        &configs,
        Budget {
            bytes: 64 << 20,
            files: 10_000,
            ..Budget::default()
        },
        &|path| source_allowed(path, &options.dirs),
    )
    .map_err(|_| Failure::new("io", "the config scan failed"))?;
    absorb(
        part,
        MachineSource::McpConfig,
        &mut machine,
        &mut r,
        &mut seen,
    );
    check_budget(&params, &machine)?;
    for m in &mut machine {
        let Some(name) = m.name().filter(|n| !looks_like_value(n)) else {
            r.keep(&m.found.source.path, kind(m.kind), None, "invalid_name");
            continue;
        };
        let Some(value) = m
            .found
            .value
            .as_ref()
            .filter(|_| m.found.disposition == Disposition::Literal && !m.found.env_file)
        else {
            r.keep(
                &m.found.source.path,
                kind(m.kind),
                Some(&name),
                "manual_assignment",
            );
            continue;
        };
        m.sent = Some(params.entries.len());
        params.entries.push(ImportEntry {
            scope: ImportScope::Machine(MachineScope {
                source: m.kind,
                label: project_name(&m.found.source.path),
            }),
            file: display_path(&m.found.source.path),
            line: 1,
            profile: None,
            name,
            value: WireSecret::new(secret_copy(value)),
        });
    }
    let mut plan = ImportPlanView {
        digest: String::new(),
        entries: Vec::new(),
        items: Vec::new(),
    };
    let mut compared = 0u64;
    let mut skipped_guessable = 0u64;
    if !params.entries.is_empty() {
        require_unlocked(&mut connect()?)?;
        let mut candidates = Candidates::counted(Budget::default())
            .map_err(|_| Failure::new("io", "could not prepare candidates"))?;
        for e in &params.entries {
            if e.value.as_secret().len() > envcloak_ipc::proto::MAX_CANDIDATE
                || e.value.as_secret().is_empty()
            {
                continue;
            }
            if !candidates.insert(Candidate {
                id: 0,
                value: secret_copy(e.value.as_secret()),
                form: Form::Raw,
                occurrence: Occurrence {
                    source: Default::default(),
                    range: 0..0,
                    encoding: Encoding::Raw,
                    stamp: None,
                    rewritable: false,
                },
            }) {
                return Err(Failure::new("limited", "the candidate budget was reached"));
            }
        }
        let mut batch = Vec::new();
        for c in candidates.into_entries() {
            batch.push(ScanCandidate {
                id: c.id as u32,
                value: WireSecret::new(c.value),
                form: CandidateForm::Raw,
            });
            if batch.len() == 64 {
                compare(
                    std::mem::take(&mut batch),
                    &mut compared,
                    &mut skipped_guessable,
                )?;
            }
        }
        if !batch.is_empty() {
            compare(batch, &mut compared, &mut skipped_guessable)?;
        }
        plan = connect()?.import_plan(&params).map_err(too_large)?;
    }
    pause_point("first_run_planned");
    let committed = options.yes && !params.entries.is_empty();
    if committed {
        plan = connect()?
            .import_commit(&ImportCommitParams {
                import: params,
                digest: plan.digest.clone(),
            })
            .map_err(too_large)?;
        pause_point("first_run_committed");
    }
    let mut legacy_projects = Vec::new();
    for g in &groups {
        let local = ImportPlanView {
            digest: plan.digest.clone(),
            items: plan.items.clone(),
            entries: plan
                .entries
                .iter()
                .skip(g.start)
                .take(g.sent.len())
                .cloned()
                .collect(),
        };
        let mut report = super::report(
            &g.root,
            &g.projects,
            Some(&local),
            &g.sent,
            g.skipped.clone(),
        );
        if committed {
            for pi in 0..g.projects.len() {
                write_project(
                    &g.root,
                    &g.projects,
                    pi,
                    &local,
                    &g.sent,
                    &mut report.projects[pi],
                );
                let p = &report.projects[pi];
                if p.manifest == Some(FileChange::Refused)
                    || p.gitignore == Some(FileChange::Refused)
                    || !p.conflicts.is_empty()
                    || p.resolves == Some(false)
                {
                    r.fail(Path::new(&p.dir), "dotenv", "project_write_failed");
                }
            }
        }
        for (n, (pi, fi, ei)) in g.sent.iter().enumerate() {
            let path = g.root.path().join(&g.projects[*pi].files[*fi].rel);
            if let Some(e) = local.entries.get(n) {
                if e.item.is_some() && committed {
                    let s = r.source(&path, "dotenv");
                    s["imported"] = json!(s["imported"].as_u64().unwrap_or(0) + 1);
                } else if let Some(reason) = e.skipped {
                    r.keep(
                        &path,
                        "dotenv",
                        g.projects[*pi].files[*fi]
                            .parsed
                            .as_ref()
                            .ok()
                            .and_then(|p| p.get(*ei))
                            .map(|e| e.name.as_str()),
                        reason.token(),
                    );
                }
            }
        }
        let mut old = report.json();
        sanitize_legacy(&mut old, None);
        legacy_projects.extend(old["projects"].as_array().cloned().unwrap_or_default());
    }
    let mut migrate = Vec::new();
    for m in &machine {
        let name = m.name();
        let Some(entry) = m.sent.and_then(|i| plan.entries.get(i)) else {
            continue;
        };
        if let Some(item) = entry.item.and_then(|i| plan.items.get(i as usize)) {
            if committed {
                let s = r.source(&m.found.source.path, kind(m.kind));
                s["imported"] = json!(s["imported"].as_u64().unwrap_or(0) + 1);
            }
            if m.kind == MachineSource::McpConfig {
                migrate.push(json!({"display_path":display_path(&m.found.source.path),"name":name,"slug":safe_name(&item.slug),"command":"envcloak agents migrate-mcp"}));
                r.keep(
                    &m.found.source.path,
                    kind(m.kind),
                    name.as_deref(),
                    "migrate_mcp_required",
                );
            } else if !options.delete {
                r.keep(
                    &m.found.source.path,
                    kind(m.kind),
                    name.as_deref(),
                    "delete_not_requested",
                );
            } else if !m.found.single_complete_line {
                r.keep(
                    &m.found.source.path,
                    kind(m.kind),
                    name.as_deref(),
                    "manual_assignment",
                );
            }
        } else {
            r.keep(
                &m.found.source.path,
                kind(m.kind),
                name.as_deref(),
                entry.skipped.map(|s| s.token()).unwrap_or("not_imported"),
            );
        }
    }
    if committed && options.delete {
        cleanup::run(&groups, &machine, &plan, &mut r)?;
    }
    let mut leaked = Vec::new();
    let mut items = Vec::new();
    for item in &plan.items {
        let mut value = serde_json::to_value(item)
            .map_err(|_| Failure::new("internal", "cannot encode import metadata"))?;
        sanitize_legacy(&mut value, None);
        value["scope"] = json!(if item.projects > 0 {
            "project"
        } else {
            "machine"
        });
        value["providers"] = json!(
            item.provider
                .iter()
                .map(|s| safe_name(s))
                .collect::<Vec<_>>()
        );
        value["owning_account"] = json!("unknown");
        let mut referenced = BTreeSet::new();
        for m in &machine {
            if m.sent
                .and_then(|i| plan.entries.get(i))
                .and_then(|e| e.item)
                .is_some_and(|i| plan.items[i as usize].slug == item.slug)
            {
                referenced.insert(display_path(&m.found.source.path));
            }
        }
        for g in &groups {
            for (n, (pi, fi, _)) in g.sent.iter().enumerate() {
                if plan
                    .entries
                    .get(g.start + n)
                    .and_then(|e| e.item)
                    .is_some_and(|i| plan.items[i as usize].slug == item.slug)
                {
                    referenced.insert(display_path(
                        &g.root.path().join(&g.projects[*pi].files[*fi].rel),
                    ));
                }
            }
        }
        value["referenced_by"] = json!(referenced);
        if item.existing || committed {
            match connect()?.items_show(&item.slug) {
                Ok(metadata) if metadata.exposed.is_some() => leaked
                    .push(json!({"slug":safe_name(&item.slug),"status":"already leaked: rotate"})),
                Ok(_) => (),
                Err(_) => {
                    r.incomplete.insert("metadata_unavailable".into());
                }
            }
        }
        items.push(value);
    }
    let duplicates = plan
        .items
        .iter()
        .map(|i| i.entries.saturating_sub(1) as u64)
        .sum::<u64>();
    let report = json!({"schema":"first_run.v1","committed":committed,"sources":r.sources.values().collect::<Vec<_>>(),"items":items,"leaked":leaked,
        "duplicates_merged":duplicates,"compared":compared,"skipped_guessable":skipped_guessable,"migrate_mcp":migrate,"backups":r.backups,"incomplete":r.incomplete,
        "projects":legacy_projects,"skipped":groups.iter().flat_map(|g|g.skipped.iter().map(|s|json!({"path":display_path(Path::new(&s.path)),"reason":s.reason}))).collect::<Vec<_>>()});
    if options.json {
        println!("{}", json_text(&report));
    } else {
        println!(
            "First-run import: {} items, {duplicates} duplicates merged. Owning accounts: unknown.",
            plan.items.len()
        );
        for item in &plan.items {
            println!(
                "  {} ({}, provider: {})",
                safe_name(&item.slug),
                if item.projects > 0 {
                    "project"
                } else {
                    "machine"
                },
                item.provider
                    .as_deref()
                    .map(safe_name)
                    .unwrap_or_else(|| "unknown".into())
            );
        }
        for item in report["leaked"].as_array().into_iter().flatten() {
            println!(
                "  {}: already leaked; rotate",
                item["slug"].as_str().unwrap_or(HIDDEN)
            );
        }
        for source in r.sources.values() {
            println!(
                "{}: {} found, {} imported",
                source["display_path"].as_str().unwrap_or(HIDDEN),
                source["found"],
                source["imported"]
            );
            for kept in source["kept"].as_array().into_iter().flatten() {
                println!(
                    "  kept {}: {}",
                    kept["name"].as_str().unwrap_or("entry"),
                    kept["reason"].as_str().unwrap_or("unknown")
                );
            }
            if let Some(replacement) = source["replacement"].as_str() {
                println!("  replacement: {replacement}");
            }
            if let Some(manual) = source["manual"].as_str() {
                println!("  manual: {manual}");
            }
            if let Some(cleanup) = source["cleanup"].as_str() {
                println!("  cleanup: {cleanup}");
            }
            if let Some(receipt) = source["receipt"].as_str() {
                println!("  backup receipt: {receipt}");
            }
        }
        if !report["migrate_mcp"]
            .as_array()
            .is_none_or(|m| m.is_empty())
        {
            println!(
                "MCP literals stay in place; use envcloak agents migrate-mcp with the listed item names."
            );
        }
        if !committed {
            println!("Dry run: nothing imported. Use --yes to import.");
        }
        if !r.incomplete.is_empty() {
            println!(
                "Incomplete: {}",
                r.incomplete.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
    }
    Ok(if r.incomplete.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(FAILURE)
    })
}
fn sanitize_legacy(value: &mut Value, key: Option<&str>) {
    match value {
        Value::Object(fields) => {
            fields.remove("line");
            fields.remove("error_line");
            for (k, v) in fields {
                sanitize_legacy(v, Some(k));
            }
        }
        Value::Array(values) => {
            for v in values {
                sanitize_legacy(v, key);
            }
        }
        Value::String(text) => {
            *text = if matches!(key, Some("dir" | "root" | "path" | "file")) {
                display_path(Path::new(text))
            } else {
                safe_name(text)
            };
        }
        _ => (),
    }
}
fn compare(
    candidates: Vec<ScanCandidate>,
    compared: &mut u64,
    skipped: &mut u64,
) -> Result<(), Failure> {
    let view = connect()?.scan_match(&ScanMatchParams {
        candidates,
        source_kind: ScanSource::Mixed,
        purpose: ScanPurpose::Import,
        claims: claims(),
    })?;
    *compared += u64::from(view.compared);
    *skipped += u64::from(view.skipped_guessable);
    if view.limited {
        return Err(Failure::new(
            "limited",
            "the import comparison budget was reached",
        ));
    }
    Ok(())
}
