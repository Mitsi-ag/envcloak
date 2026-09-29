//! `envcloak import --scan <dir> [--yes] [--json]` (SPEC §6.4): imports
//! the env files of every project under `<dir>`, deduplicating identical
//! values into one item that many projects reference. Without `--yes` it
//! is a dry run: the report says what would happen, and nothing is
//! written anywhere.
//!
//! The steps, shared with `envcloak init --import` ([`scan`],
//! [`import_params`], [`write_project`]):
//! 1. The scan runs here, in the CLI (`envcloak_scan`): through directory
//!    handles, never following a symlink, crossing a mount point or
//!    waiting on a FIFO; dependency and cache directories are skipped.
//!    Every directory holding `.env` or `.env.<profile>` files is a
//!    project. Each file is read whole into a wiped buffer (at most
//!    1 MiB) and parsed without expanding anything. Template files
//!    (`.env.example`, ...) are read for their names only: their values
//!    never leave this process.
//! 2. A verified daemon gets each entry's value and works out the plan
//!    (`import.plan`): which values are secrets, which items hold them
//!    already, what new items are called. The CLI has no key, so it
//!    compares nothing itself.
//! 3. With `--yes` the daemon commits that plan, and only that plan
//!    (`import.commit` checks its digest). Each project then gets its
//!    bindings in `envcloak.toml`, written atomically: a new manifest is
//!    created only where none exists, and in an existing one a variable
//!    bound to another item already is left as it is and reported. Each
//!    env file is added to the project's `.gitignore` unless a line there
//!    already names it; references-only files are not. Last, the daemon
//!    checks every reference of the manifest resolves: the dry run.
//!
//! The report holds paths, variable names, lines and slugs; never a value.
//! A name shaped like a key is not shown.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use envcloak_core::SecretBytes;
use envcloak_ipc::WireSecret;
use envcloak_ipc::proto::{ImportCommitParams, ImportEntry, ImportParams, ImportProject};
use envcloak_ipc::view::{
    EntryReport, FileChange, FileReport, ImportPlanView, ImportReport, ProjectReport, SkipReason,
    SkippedPath,
};
use envcloak_policy::{Binding, EnvName, MANIFEST_NAME, ProfileName, Reference, parse_manifest};
use envcloak_scan::{
    DotenvEntry, DotenvError, EntryKind, FileKind, FileStamp, MAX_DOTENV, ScanRoot, WalkOptions,
    create_atomically, open_root, parse_dotenv, pause_point, read_capped, read_plain,
    replace_atomically, walk_dotenv,
};

use super::{claims, require_unlocked};
use crate::connect::connect;
use crate::fail::{FAILURE, Failure, usage};
use crate::render::{looks_like_value, print};

const USAGE: &str = "envcloak import --scan <dir> [--yes] [--json]";

/// An env file read for an import or a deletion.
pub(crate) struct ReadFile {
    /// Relative to the scan root.
    pub rel: PathBuf,
    pub profile: Option<ProfileName>,
    pub template: bool,
    pub hard_linked: bool,
    pub stamp: FileStamp,
    pub bytes: SecretBytes,
    /// The parse, for the report. Parsing `bytes` again gives the same
    /// entries: each request gets fresh copies of the values, and these
    /// are wiped when the file is dropped.
    pub parsed: Result<Vec<DotenvEntry>, DotenvError>,
}

impl ReadFile {
    /// The file's name, which is UTF-8 (the scan keeps no other).
    pub fn file_name(&self) -> &str {
        self.rel
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
    }

    /// Whether every entry is an `envcloak://` reference: such a file holds
    /// no secret, is not imported, ignored or deleted.
    pub fn references_only(&self) -> bool {
        matches!(&self.parsed, Ok(e) if !e.is_empty()
            && e.iter().all(|x| matches!(x.kind, EntryKind::Reference(_))))
    }
}

/// A directory with env files.
pub(crate) struct Project {
    /// Relative to the scan root; empty for the root itself.
    pub rel_dir: PathBuf,
    /// One slug part: new items are named `<base>/<name>`.
    pub name: String,
    pub files: Vec<ReadFile>,
}

/// The absolute path of `rel_dir` under `root`, without a trailing `/`
/// for the root itself.
pub(crate) fn dir_of(root: &ScanRoot, rel_dir: &Path) -> PathBuf {
    if rel_dir.as_os_str().is_empty() {
        root.path().to_path_buf()
    } else {
        root.path().join(rel_dir)
    }
}

/// A slug part from a directory's name: lowercase letters, digits, `.`,
/// `_` and `-`, starting with a letter or digit.
pub(crate) fn project_name(dir: &Path) -> String {
    let raw = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let mut s = String::new();
    for c in raw.chars() {
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
            c
        } else {
            '-'
        };
        if !(c == '-' && s.ends_with('-')) {
            s.push(c);
        }
    }
    let s = s.trim_start_matches(['.', '_', '-']);
    let mut s = s.to_owned();
    s.truncate(60);
    let s = s.trim_end_matches(['.', '_', '-']).to_owned();
    if s.is_empty() {
        "project".to_owned()
    } else {
        s
    }
}

/// Scans `root` (and below it when `recursive`), reads every env file, and
/// groups them by directory. Paths that were not read are listed with why.
pub(crate) fn scan(root: &ScanRoot, recursive: bool) -> (Vec<Project>, Vec<SkippedPath>) {
    let options = WalkOptions {
        recursive,
        ..WalkOptions::default()
    };
    let mut skipped = Vec::new();
    let mut by_dir: BTreeMap<PathBuf, Vec<ReadFile>> = BTreeMap::new();
    for found in walk_dotenv(root, &options) {
        let f = match found {
            Ok(f) => f,
            Err(e) => {
                skipped.push(SkippedPath {
                    path: e.rel.to_string_lossy().into_owned(),
                    reason: e.kind.token().to_owned(),
                });
                continue;
            }
        };
        if f.rel.to_str().is_none() {
            skipped.push(SkippedPath {
                path: f.rel.to_string_lossy().into_owned(),
                reason: "not_utf8".to_owned(),
            });
            continue;
        }
        let (bytes, stamp) = match read_capped(root, &f.rel, MAX_DOTENV) {
            Ok(x) => x,
            Err(e) => {
                skipped.push(SkippedPath {
                    path: e.rel.to_string_lossy().into_owned(),
                    reason: e.kind.token().to_owned(),
                });
                continue;
            }
        };
        let parsed = parse_dotenv(&bytes);
        let (profile, template) = match f.kind {
            FileKind::Dotenv { profile } => (profile, false),
            FileKind::Template => (None, true),
        };
        let dir = f.rel.parent().map(Path::to_path_buf).unwrap_or_default();
        by_dir.entry(dir).or_default().push(ReadFile {
            rel: f.rel,
            profile,
            template,
            hard_linked: f.hard_linked,
            stamp,
            bytes,
            parsed,
        });
    }
    let projects = by_dir
        .into_iter()
        .map(|(rel_dir, files)| Project {
            name: project_name(&root.path().join(&rel_dir)),
            rel_dir,
            files,
        })
        .collect();
    (projects, skipped)
}

/// Where each entry sent came from: project, file and entry indices.
pub(crate) type Sent = Vec<(usize, usize, usize)>;

/// The entries to send: every plain entry of every file that is not a
/// template, with a fresh copy of its value, and where each came from.
pub(crate) fn import_params(
    root: &ScanRoot,
    projects: &[Project],
    claims: Vec<String>,
) -> (ImportParams, Sent) {
    let mut entries = Vec::new();
    let mut sent = Vec::new();
    let mut out_projects = Vec::with_capacity(projects.len());
    for (pi, p) in projects.iter().enumerate() {
        out_projects.push(ImportProject {
            dir: dir_of(root, &p.rel_dir).to_string_lossy().into_owned(),
            name: p.name.clone(),
        });
        for (fi, f) in p.files.iter().enumerate() {
            if f.template || f.parsed.is_err() {
                continue;
            }
            let Ok(parsed) = parse_dotenv(&f.bytes) else {
                continue;
            };
            for (ei, e) in parsed.into_iter().enumerate() {
                if e.kind != EntryKind::Plain {
                    continue;
                }
                entries.push(ImportEntry {
                    project: u32::try_from(pi).unwrap_or(u32::MAX),
                    file: f.file_name().to_owned(),
                    line: e.line,
                    profile: f.profile.as_ref().map(|p| p.as_str().to_owned()),
                    name: e.name.as_str().to_owned(),
                    value: WireSecret::new(e.value),
                });
                sent.push((pi, fi, ei));
            }
        }
    }
    (
        ImportParams {
            projects: out_projects,
            entries,
            claims,
        },
        sent,
    )
}

/// A name as a report may show it: `None` when it looks like a value.
fn name_shown(n: &EnvName) -> Option<String> {
    (!looks_like_value(n.as_str())).then(|| n.as_str().to_owned())
}

/// The report of one project's files, with the plan's fate for each entry.
fn file_reports(
    p: &Project,
    pi: usize,
    plan: Option<&ImportPlanView>,
    sent: &Sent,
) -> Vec<FileReport> {
    // Where each (file, entry) went in the plan.
    let mut fate: BTreeMap<(usize, usize), usize> = BTreeMap::new();
    for (i, (sp, sf, se)) in sent.iter().enumerate() {
        if *sp == pi {
            fate.insert((*sf, *se), i);
        }
    }
    p.files
        .iter()
        .enumerate()
        .map(|(fi, f)| {
            let (entries, error_line, error) = match &f.parsed {
                Err(e) => (
                    Vec::new(),
                    Some(e.line()),
                    Some(e.kind().token().to_owned()),
                ),
                Ok(parsed) => (
                    parsed
                        .iter()
                        .enumerate()
                        .map(|(ei, e)| {
                            let planned = fate
                                .get(&(fi, ei))
                                .and_then(|&i| plan.and_then(|p| p.entries.get(i)));
                            let skipped = match &e.kind {
                                _ if f.template => None,
                                EntryKind::Reference(_) => Some(SkipReason::Reference),
                                EntryKind::Template => Some(SkipReason::Interpolated),
                                EntryKind::Plain => planned.and_then(|p| p.skipped),
                            };
                            EntryReport {
                                line: e.line,
                                name: name_shown(&e.name),
                                item: planned.and_then(|p| p.item),
                                skipped,
                            }
                        })
                        .collect(),
                    None,
                    None,
                ),
            };
            FileReport {
                file: f.file_name().to_owned(),
                profile: f.profile.as_ref().map(|p| p.as_str().to_owned()),
                template: f.template,
                hard_linked: f.hard_linked,
                error_line,
                error,
                entries,
            }
        })
        .collect()
}

/// The report of every project, before anything is written.
pub(crate) fn report(
    root: &ScanRoot,
    projects: &[Project],
    plan: Option<&ImportPlanView>,
    sent: &Sent,
    skipped: Vec<SkippedPath>,
) -> ImportReport {
    ImportReport {
        root: root.path().to_string_lossy().into_owned(),
        committed: false,
        projects: projects
            .iter()
            .enumerate()
            .map(|(pi, p)| ProjectReport {
                dir: dir_of(root, &p.rel_dir).to_string_lossy().into_owned(),
                name: p.name.clone(),
                files: file_reports(p, pi, plan, sent),
                manifest: None,
                conflicts: Vec::new(),
                gitignore: None,
                resolves: None,
            })
            .collect(),
        items: plan.map(|p| p.items.clone()).unwrap_or_default(),
        skipped,
    }
}

/// The bindings the plan gives project `pi`, by profile (`None` for
/// `[env]`): variable to reference. A profile's binding that equals the
/// default's is left out, since profiles inherit `[env]`.
fn bindings_for(
    projects: &[Project],
    pi: usize,
    plan: &ImportPlanView,
    sent: &Sent,
) -> BTreeMap<Option<ProfileName>, BTreeMap<EnvName, String>> {
    let mut out: BTreeMap<Option<ProfileName>, BTreeMap<EnvName, String>> = BTreeMap::new();
    for (i, (sp, sf, se)) in sent.iter().enumerate() {
        if *sp != pi {
            continue;
        }
        let Some(item) = plan
            .entries
            .get(i)
            .and_then(|e| e.item)
            .and_then(|at| plan.items.get(usize::try_from(at).ok()?))
        else {
            continue;
        };
        let f = &projects[pi].files[*sf];
        let Ok(parsed) = &f.parsed else { continue };
        let Some(e) = parsed.get(*se) else { continue };
        out.entry(f.profile.clone())
            .or_default()
            .insert(e.name.clone(), item.reference.clone());
    }
    let default = out.get(&None).cloned().unwrap_or_default();
    for (profile, map) in out.iter_mut() {
        if profile.is_some() {
            map.retain(|name, r| default.get(name) != Some(r));
        }
    }
    out.retain(|_, m| !m.is_empty());
    out
}

/// A TOML basic string.
fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A new manifest with `bindings`.
fn new_manifest(
    name: &str,
    bindings: &BTreeMap<Option<ProfileName>, BTreeMap<EnvName, String>>,
) -> String {
    let mut t = String::from(
        "# Written by `envcloak init`. Names only: the values are in the EnvCloak vault.\n\
         [project]\n",
    );
    t.push_str(&format!("name = {}\n\n[env]\n", quoted(name)));
    if let Some(env) = bindings.get(&None) {
        for (k, v) in env {
            t.push_str(&format!("{k} = {}\n", quoted(v)));
        }
    }
    for (profile, map) in bindings {
        let Some(p) = profile else { continue };
        t.push_str(&format!("\n[env.{p}]\n"));
        for (k, v) in map {
            t.push_str(&format!("{k} = {}\n", quoted(v)));
        }
    }
    t
}

/// Whether a line of a `.gitignore` already ignores the env file `name`
/// in its directory: the name itself (anchored or not), or the usual
/// `.env*` patterns. Not a full matcher: a line it misses only makes a
/// duplicate.
fn ignored_by(line: &str, name: &str) -> bool {
    let l = line.trim();
    if l.is_empty() || l.starts_with('#') || l.starts_with('!') {
        return false;
    }
    let l = l.strip_prefix('/').unwrap_or(l);
    let l = l.strip_prefix("**/").unwrap_or(l);
    l == name || l == ".env*" || (l == ".env.*" && name.starts_with(".env."))
}

/// The `.gitignore` line for the temporary names a change of an env file
/// uses (`..env.envcloak-del-<hex>.tmp`): a crash can leave plaintext
/// under one, which the lines for the env files do not cover.
pub(crate) const TEMP_PATTERN: &str = ".*.envcloak-*.tmp";

/// `.gitignore` in `rel_dir` with a line for each of `names` it lacks, and
/// then [`TEMP_PATTERN`] too. The file's own bytes are kept as they are,
/// UTF-8 or not: lines are only added after them.
fn edit_gitignore(root: &ScanRoot, rel_dir: &Path, names: &[&str]) -> FileChange {
    if names.is_empty() {
        return FileChange::Unchanged;
    }
    let rel = rel_dir.join(".gitignore");
    let (bytes, stamp) = match read_plain(root, &rel, MAX_DOTENV) {
        Ok((bytes, stamp)) => (bytes, Some(stamp)),
        Err(e) if e.kind == envcloak_scan::ScanErrorKind::NotFound => (Vec::new(), None),
        Err(_) => return FileChange::Refused,
    };
    // Read lossily only to see which lines are there; a line it misreads
    // can only make a duplicate.
    let text = String::from_utf8_lossy(&bytes);
    let missing: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| !text.lines().any(|l| ignored_by(l, n)))
        .collect();
    if missing.is_empty() {
        return FileChange::Unchanged;
    }
    let mut new = bytes.clone();
    if !new.is_empty() && !new.ends_with(b"\n") {
        new.push(b'\n');
    }
    if !new.is_empty() {
        new.push(b'\n');
    }
    new.extend_from_slice(b"# Plaintext env files stay out of git (envcloak init).\n");
    for n in missing {
        new.push(b'/');
        new.extend_from_slice(n.as_bytes());
        new.push(b'\n');
    }
    if !text.lines().any(|l| l.trim() == TEMP_PATTERN) {
        new.extend_from_slice(TEMP_PATTERN.as_bytes());
        new.push(b'\n');
    }
    let written = match stamp {
        Some(s) => replace_atomically(root, &rel, &new, &s).map(|_| FileChange::Updated),
        None => create_atomically(root, &rel, &new, 0o644).map(|_| FileChange::Created),
    };
    written.unwrap_or(FileChange::Refused)
}

/// Writes project `pi`'s bindings to its manifest and its env files to its
/// `.gitignore`, then asks the daemon whether every reference resolves.
pub(crate) fn write_project(
    root: &ScanRoot,
    projects: &[Project],
    pi: usize,
    plan: &ImportPlanView,
    sent: &Sent,
    out: &mut ProjectReport,
) {
    let p = &projects[pi];
    let bindings = bindings_for(projects, pi, plan, sent);
    let manifest_rel = p.rel_dir.join(MANIFEST_NAME);
    let manifest_path = root.path().join(&manifest_rel);
    out.manifest = Some(
        match read_plain(root, &manifest_rel, envcloak_policy::Manifest::MAX_LEN) {
            Err(e) if e.kind == envcloak_scan::ScanErrorKind::NotFound => {
                if bindings.is_empty() {
                    FileChange::Unchanged
                } else {
                    let text = new_manifest(&p.name, &bindings);
                    if parse_manifest(text.as_bytes()).is_err() {
                        FileChange::Refused
                    } else {
                        create_atomically(root, &manifest_rel, text.as_bytes(), 0o644)
                            .map_or(FileChange::Refused, |_| FileChange::Created)
                    }
                }
            }
            Err(_) => FileChange::Refused,
            Ok(_) => update_manifest(&manifest_path, &bindings, &mut out.conflicts),
        },
    );
    let names: Vec<&str> = p
        .files
        .iter()
        .filter(|f| !f.template && !f.references_only())
        .map(ReadFile::file_name)
        .collect();
    out.gitignore = Some(edit_gitignore(root, &p.rel_dir, &names));
    if manifest_path.is_file() {
        out.resolves = connect()
            .ok()
            .and_then(|mut c| c.items_check(manifest_path.to_str(), &[]).ok())
            .map(|v| v.bindings.iter().all(|b| b.status.is_ok()));
    }
}

/// Adds the bindings an existing manifest lacks, one atomic edit each
/// ([`super::ref_::edit_manifest_ref`]). A variable bound to another
/// reference already is left alone and named in `conflicts`.
fn update_manifest(
    path: &Path,
    bindings: &BTreeMap<Option<ProfileName>, BTreeMap<EnvName, String>>,
    conflicts: &mut Vec<String>,
) -> FileChange {
    let Ok(bytes) = std::fs::read(path) else {
        return FileChange::Refused;
    };
    let Ok(m) = parse_manifest(&bytes) else {
        return FileChange::Refused;
    };
    let mut changed = false;
    for (profile, map) in bindings {
        let table = match profile {
            None => Some(&m.env),
            Some(p) => m.profiles.get(p),
        };
        for (name, reference) in map {
            let Ok(r) = Reference::parse(reference) else {
                continue;
            };
            match table.and_then(|t| t.iter().find(|b| b.env_name == *name)) {
                Some(b) if b.reference == r => continue,
                Some(_) => {
                    conflicts.extend(name_shown(name));
                    continue;
                }
                None => {}
            }
            let binding = Binding {
                env_name: name.clone(),
                reference: r,
            };
            match super::ref_::edit_manifest_ref(path, &binding, profile.as_ref()) {
                Ok(_) => changed = true,
                Err(_) => return FileChange::Refused,
            }
        }
    }
    if changed {
        FileChange::Updated
    } else {
        FileChange::Unchanged
    }
}

/// Imports what `projects` hold: the plan, and with `yes` the commit and
/// each project's files. Returns the report.
pub(crate) fn import(
    root: &ScanRoot,
    projects: &[Project],
    skipped: Vec<SkippedPath>,
    yes: bool,
) -> Result<ImportReport, Failure> {
    let (params, sent) = import_params(root, projects, claims());
    if params.entries.is_empty() {
        return Ok(report(root, projects, None, &sent, skipped));
    }
    let mut client = connect()?;
    require_unlocked(&mut client)?;
    crate::fail::refuse_if_traced()?;
    let plan = client.import_plan(&params).map_err(too_large)?;
    drop(params);
    pause_point("planned");
    let mut r = report(root, projects, Some(&plan), &sent, skipped);
    if !yes {
        return Ok(r);
    }
    // The same entries again, with fresh copies of the values; the daemon
    // commits only the plan with the digest shown.
    let (params, again) = import_params(root, projects, claims());
    if again != sent {
        return Err(Failure::new(
            "internal",
            "the files parsed differently the second time",
        ));
    }
    let done = connect()?
        .import_commit(&ImportCommitParams {
            import: params,
            digest: plan.digest.clone(),
        })
        .map_err(too_large)?;
    pause_point("committed");
    r = report(root, projects, Some(&done), &sent, r.skipped);
    r.committed = true;
    for pi in 0..projects.len() {
        let mut out = r.projects[pi].clone();
        write_project(root, projects, pi, &done, &sent, &mut out);
        r.projects[pi] = out;
    }
    pause_point("written");
    Ok(r)
}

/// A request over the 1 MiB frame, as its own failure.
fn too_large(e: envcloak_ipc::ClientError) -> Failure {
    if matches!(
        e,
        envcloak_ipc::ClientError::Frame(envcloak_ipc::FrameError::TooLarge)
    ) {
        Failure::new(
            "import_too_large",
            "the env files hold too much to import in one request (over 1 MiB); import fewer \
             directories at a time",
        )
    } else {
        e.into()
    }
}

/// The parsed command line.
#[derive(Debug, Default, PartialEq, Eq)]
struct ImportArgs {
    dir: String,
    yes: bool,
    json: bool,
}

fn parse(args: &[&str]) -> Option<ImportArgs> {
    let mut a = ImportArgs::default();
    let mut dir = None;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--scan" if dir.is_none() => dir = Some(*it.next()?),
            "--yes" if !a.yes => a.yes = true,
            "--json" if !a.json => a.json = true,
            _ => return None,
        }
    }
    a.dir = dir?.to_owned();
    Some(a)
}

pub fn run(args: &[&str]) -> ExitCode {
    if args == ["--help"] || args == ["-h"] {
        println!("usage: {USAGE}");
        return ExitCode::SUCCESS;
    }
    let Some(a) = parse(args) else {
        return usage(USAGE);
    };
    run_import(&a).unwrap_or_else(|f| f.report(FAILURE))
}

fn run_import(a: &ImportArgs) -> Result<ExitCode, Failure> {
    let root = open_root(Path::new(&a.dir)).map_err(|_| {
        Failure::new(
            "scan_root",
            "the directory to scan could not be opened, or is not a directory",
        )
    })?;
    let (projects, skipped) = scan(&root, true);
    let r = import(&root, &projects, skipped, a.yes)?;
    print(&r, a.json);
    if !r.committed && !a.json && !r.items.is_empty() {
        eprintln!("envcloak: dry run: nothing was imported; run it again with --yes to import");
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_names_are_slug_parts() {
        for (dir, want) in [
            ("/x/acme-web", "acme-web"),
            ("/x/Acme Web", "acme-web"),
            ("/x/.hidden", "hidden"),
            ("/x/caf\u{e9}", "caf"),
            ("/x/---", "project"),
            ("/", "project"),
            ("/x/api_v2.1", "api_v2.1"),
        ] {
            let got = project_name(Path::new(dir));
            assert_eq!(got, want, "{dir}");
            assert!(envcloak_core::vault::Slug::new(&got).is_ok(), "{got}");
        }
    }

    #[test]
    fn gitignore_lines_that_already_cover_a_file() {
        for (line, name) in [
            (".env", ".env"),
            ("/.env", ".env"),
            ("**/.env", ".env"),
            (".env*", ".env.short"),
            ("  /.env.* ", ".env.short"),
        ] {
            assert!(ignored_by(line, name), "{line} {name}");
        }
        for (line, name) in [
            ("# .env", ".env"),
            ("!.env", ".env"),
            (".env.*", ".env"),
            (".envrc", ".env"),
            ("", ".env"),
        ] {
            assert!(!ignored_by(line, name), "{line} {name}");
        }
    }

    /// A `.gitignore` that is not UTF-8 keeps its bytes: the lines are
    /// added after them, once, with the temporary-name line.
    #[test]
    fn gitignore_bytes_are_kept_and_lines_added_once() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let latin1 = b"caf\xe9/\n# \xff\xfe kept\nbuild";
        std::fs::write(d.path().join(".gitignore"), latin1).unwrap();
        let root = open_root(d.path()).unwrap();
        let change = edit_gitignore(&root, Path::new(""), &[".env", ".env.short"]);
        assert_eq!(change, FileChange::Updated);
        let got = std::fs::read(d.path().join(".gitignore")).unwrap();
        let mut want = latin1.to_vec();
        want.extend_from_slice(
            b"\n\n# Plaintext env files stay out of git (envcloak init).\n/.env\n/.env.short\n",
        );
        want.extend_from_slice(TEMP_PATTERN.as_bytes());
        want.push(b'\n');
        assert_eq!(got, want);
        let again = edit_gitignore(&root, Path::new(""), &[".env", ".env.short"]);
        assert_eq!(again, FileChange::Unchanged);
        assert_eq!(std::fs::read(d.path().join(".gitignore")).unwrap(), want);
        // A new env file later: its line, and no second temporary-name line.
        let more = edit_gitignore(&root, Path::new(""), &[".env", ".env.local"]);
        assert_eq!(more, FileChange::Updated);
        let text = String::from_utf8_lossy(&std::fs::read(d.path().join(".gitignore")).unwrap())
            .into_owned();
        assert_eq!(text.lines().filter(|l| *l == TEMP_PATTERN).count(), 1);
        assert!(text.lines().any(|l| l == "/.env.local"));
    }

    #[test]
    fn manifests_are_written_to_parse() {
        let mut b = BTreeMap::new();
        let mut env = BTreeMap::new();
        env.insert(EnvName::new("A").unwrap(), "a/x".to_owned());
        b.insert(None, env);
        let mut short = BTreeMap::new();
        short.insert(EnvName::new("B").unwrap(), "b/x#field".to_owned());
        b.insert(Some(ProfileName::new("short").unwrap()), short);
        let text = new_manifest("acme-web", &b);
        let m = parse_manifest(text.as_bytes()).unwrap();
        assert_eq!(m.project_name.as_deref(), Some("acme-web"));
        assert_eq!(m.env.len(), 1);
        assert_eq!(m.profiles.len(), 1);
    }
}
