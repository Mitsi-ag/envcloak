//! Descriptor-relative discovery shared by configs and transcript stores.
use crate::candidates::{Budget, Leftover, ScanReport, Source};
use crate::source::{ConfigFormat, ConfigSource, SourceKind};
use crate::{FileStamp, ScanErrorKind, ScanRoot};
use envcloak_sys::{DirEntryKind, list_dir, open_dir_beneath};
use std::fs::{File, Metadata};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[derive(Default)]
struct Visits {
    files: std::collections::HashMap<PathBuf, ReadState>,
    omissions: Vec<ConfigSource>,
}
enum ReadState {
    Closed,
    Read(std::collections::HashSet<ConfigFormat>),
}
impl Visits {
    fn omitted(&self, path: &Path, directory: bool) -> Option<&ConfigSource> {
        omitted_source(&self.omissions, path, directory)
    }
}

fn omitted_kind(kind: SourceKind) -> bool {
    matches!(kind, SourceKind::Database | SourceKind::Credentials)
}

/// Whether a catalog credential store or database forbids reading this path.
pub fn omitted_path(sources: &[ConfigSource], path: &Path) -> bool {
    omitted_source(sources, path, false).is_some()
}

fn omitted_source<'a>(
    sources: &'a [ConfigSource],
    path: &Path,
    directory: bool,
) -> Option<&'a ConfigSource> {
    sources
        .iter()
        .filter(|s| omitted_kind(s.source_kind) && (!directory || s.names.is_none()))
        .find(|s| {
            let Ok(root) = system_path(&s.path) else {
                return false;
            };
            // Catalog names must remain omitted through case aliases on
            // insensitive volumes. Conservatively omit those spellings on
            // sensitive volumes too, without resolving user-controlled links.
            let mut parts = path.components();
            if !root.components().all(|r| {
                parts.next().is_some_and(|p| {
                    p.as_os_str()
                        .as_bytes()
                        .eq_ignore_ascii_case(r.as_os_str().as_bytes())
                })
            }) {
                return false;
            }
            let rest = parts.as_path();
            if rest.as_os_str().is_empty() {
                return true;
            }
            match &s.names {
                None => true,
                Some(name) => {
                    rest.components().count() == 1
                        && rest.file_name().is_some_and(|n| {
                            n.as_bytes()
                                .windows(name.len().max(1))
                                .any(|w| w.eq_ignore_ascii_case(name.as_bytes()))
                        })
                }
            }
        })
}

pub(crate) fn effective_format(path: &Path, format: ConfigFormat) -> ConfigFormat {
    if format == ConfigFormat::Mixed {
        if path.extension().is_some_and(|ext| ext == "jsonl") {
            ConfigFormat::Jsonl
        } else {
            ConfigFormat::Raw
        }
    } else {
        format
    }
}

/// Opens a catalog-selected or sealed restore directory without following any user-controlled
/// component. Only root-owned, fixed-target macOS system aliases are resolved.
pub fn absolute_root(path: &Path) -> Result<ScanRoot, ScanErrorKind> {
    if !path.is_absolute() {
        return Err(ScanErrorKind::InvalidPath);
    }
    let path = system_path(path)?;
    let mut dir = File::open("/").map_err(|e| crate::root::io_kind(&e))?;
    for c in path.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(name) => {
                dir = open_dir_beneath(&dir, name).map_err(|e| {
                    if e.raw_os_error() == Some(libc::ENOTDIR) {
                        ScanErrorKind::Symlink
                    } else {
                        crate::root::io_kind(&e)
                    }
                })?;
            }
            _ => return Err(ScanErrorKind::InvalidPath),
        }
    }
    crate::root::held_root(path, dir).map_err(|e| crate::root::io_kind(&e))
}

fn system_path(path: &Path) -> Result<PathBuf, ScanErrorKind> {
    #[cfg(target_os = "macos")]
    for alias in ["/tmp", "/var", "/etc"] {
        if let Ok(rest) = path.strip_prefix(alias) {
            let metadata =
                std::fs::symlink_metadata(alias).map_err(|e| crate::root::io_kind(&e))?;
            if metadata.file_type().is_symlink() {
                let target = std::fs::read_link(alias).map_err(|e| crate::root::io_kind(&e))?;
                let target =
                    trusted_alias(alias, metadata.uid(), &target).ok_or(ScanErrorKind::Symlink)?;
                return Ok(Path::new(target).join(rest));
            }
        }
    }
    Ok(path.to_path_buf())
}

#[cfg(target_os = "macos")]
fn trusted_alias(alias: &str, uid: u32, target: &Path) -> Option<&'static str> {
    let expected = match alias {
        "/tmp" => "/private/tmp",
        "/var" => "/private/var",
        "/etc" => "/private/etc",
        _ => return None,
    };
    if uid == 0 && (target == Path::new(expected) || target == Path::new(&expected[1..])) {
        Some(expected)
    } else {
        None
    }
}

/// A strict name shape, not ownership evidence. Includes interrupted restore
/// staging and displaced swap files beside non-env files.
pub fn restore_leftover_name(name: &std::ffi::OsStr) -> bool {
    let b = name.as_bytes();
    if !b.starts_with(b".") {
        return false;
    }
    for tag in [
        b".envcloak-new-".as_slice(),
        b".envcloak-swap-",
        b".envcloak-del-",
    ] {
        if let Some(i) = b.windows(tag.len()).rposition(|s| s == tag) {
            if i <= 1 {
                continue;
            }
            if let Some(hex) = b[i + tag.len()..].strip_suffix(b".tmp") {
                if !hex.is_empty() && hex.iter().all(u8::is_ascii_hexdigit) {
                    return true;
                }
            }
        }
    }
    false
}

pub(crate) fn walk_sources(
    sources: &[ConfigSource],
    budget: Budget,
    report: &mut ScanReport,
    mut read: impl FnMut(&ScanRoot, &Path, &ConfigSource, (File, Metadata), &mut usize, &mut ScanReport),
) {
    let mut visited = Visits {
        omissions: sources
            .iter()
            .filter(|s| omitted_kind(s.source_kind))
            .cloned()
            .collect(),
        ..Default::default()
    };
    let mut attempts = 0usize;
    let mut source_paths = std::collections::HashSet::new();
    let mut failed_roots = std::collections::HashSet::new();
    // Omissions are policy, independent of catalog order or reader format.
    for source in sources
        .iter()
        .filter(|s| omitted_kind(s.source_kind))
        .chain(sources.iter().filter(|s| !omitted_kind(s.source_kind)))
    {
        if !source_paths.insert((
            &source.path,
            &source.names,
            source.format,
            source.source_kind,
        )) || failed_roots.contains(&source.path)
        {
            continue;
        }
        if attempts >= budget.files {
            report.issue(&source.path, "file_budget");
            break;
        }
        if report.issues.iter().any(|i| i.reason == "file_budget") {
            break;
        }
        let Some(parent) = source.path.parent() else {
            report.issue(&source.path, "invalid_path");
            continue;
        };
        let Some(name) = source.path.file_name() else {
            report.issue(&source.path, "invalid_path");
            continue;
        };
        let root = match absolute_root(parent) {
            Ok(r) => r,
            Err(ScanErrorKind::NotFound) => {
                attempts += 1;
                failed_roots.insert(source.path.clone());
                continue;
            }
            Err(e) => {
                attempts += 1;
                failed_roots.insert(source.path.clone());
                report.issue(&source.path, e.token());
                continue;
            }
        };
        match envcloak_sys::kind_beneath(root.dir(), name) {
            Ok(DirEntryKind::Dir) => {
                attempts += 1;
                let dir = match root.open_subdir(root.dir(), name) {
                    Ok(d) => d,
                    Err(e) => {
                        failed_roots.insert(source.path.clone());
                        report.issue(&source.path, e.token());
                        continue;
                    }
                };
                let sub = match crate::root::held_root(root.path().join(name), dir) {
                    Ok(r) => r,
                    Err(_) => {
                        failed_roots.insert(source.path.clone());
                        report.issue(&source.path, "io");
                        continue;
                    }
                };
                if source.source_kind == SourceKind::Credentials && source.names.is_none() {
                    note_omitted(source, sub.path(), report);
                    continue;
                }
                walk(
                    &sub,
                    Path::new(""),
                    0,
                    source,
                    budget,
                    &mut attempts,
                    &mut visited,
                    report,
                    &mut read,
                );
            }
            Ok(_) | Err(_) => {
                // Sibling candidates are reported even when the original file
                // is missing after a stopped restore.
                inspect_siblings(&root, Some(name), budget, &mut attempts, report);
                process(
                    &root,
                    Path::new(name),
                    source,
                    budget,
                    &mut attempts,
                    &mut visited,
                    report,
                    &mut read,
                    true,
                );
            }
        }
    }
}
/// Inspect only siblings of an approved include, even if its leaf is absent.
/// Parent traversal keeps the same no-follow and device rules as reading it.
pub(crate) fn inspect_optional_siblings(root: &ScanRoot, rel: &Path, report: &mut ScanReport) {
    // A missing conventional parent is normal; other discovery failures are
    // incomplete even when the original file no longer exists.
    if matches!(root.open_parent(rel), Err(crate::ScanErrorKind::NotFound)) {
        return;
    }
    let mut attempts = report.leftovers.len();
    inspect_include_siblings(root, rel, Budget::default(), &mut attempts, report);
}

/// Inspect siblings under the caller's shared discovery budget.
pub(crate) fn inspect_include_siblings(
    root: &ScanRoot,
    rel: &Path,
    budget: Budget,
    attempts: &mut usize,
    report: &mut ScanReport,
) {
    let parent = root.open_parent(rel).and_then(|(dir, name)| {
        crate::root::held_root(root.path().join(rel.parent().unwrap_or(Path::new(""))), dir)
            .map(|root| (root, name))
            .map_err(|e| crate::root::io_kind(&e))
    });
    match parent {
        Ok((parent, name)) => inspect_siblings(&parent, Some(&name), budget, attempts, report),
        // A later include read can succeed after this parent changes. Retain
        // the discovery failure independently; duplicate issues are coalesced.
        Err(e) => report.issue(root.path().join(rel), e.token()),
    }
}

fn inspect_siblings(
    root: &ScanRoot,
    base: Option<&std::ffi::OsStr>,
    budget: Budget,
    attempts: &mut usize,
    report: &mut ScanReport,
) {
    match list_dir(root.dir(), envcloak_sys::MAX_DIR_ENTRIES) {
        Ok(entries) => {
            for e in entries {
                if !restore_leftover_name(&e.name) {
                    continue;
                }
                if let Some(base) = base {
                    let name = e.name.as_bytes();
                    let base = base.as_bytes();
                    if !name.get(1..).is_some_and(|n| {
                        n.starts_with(base)
                            && n.get(base.len()..)
                                .is_some_and(|s| s.starts_with(b".envcloak-"))
                    }) {
                        continue;
                    }
                }
                if report
                    .leftovers
                    .iter()
                    .any(|l| l.source.path == root.path().join(&e.name))
                {
                    continue;
                }
                if *attempts >= budget.files {
                    report.issue(root.path(), "file_budget");
                    break;
                }
                *attempts += 1;
                leftover(root, Path::new(&e.name), report);
            }
        }
        Err(_) => report.issue(root.path(), "unreadable"),
    }
}
pub(crate) fn leftover(root: &ScanRoot, rel: &Path, report: &mut ScanReport) {
    let inspection = match root
        .open_parent(rel)
        .and_then(|(d, n)| crate::root::open_file(&d, &n, crate::MAX_DOTENV))
    {
        Ok((_, m)) => {
            if m.dev() != root.dev() {
                "mount_point"
            } else if m.nlink() > 1 {
                "hard_link"
            } else {
                "possible_leftover"
            }
        }
        Err(e) => e.token(),
    };
    let source = Source {
        path: root.path().join(rel),
        object: None,
    };
    if !report.leftovers.iter().any(|l| l.source == source) {
        report.leftovers.push(Leftover {
            source: source.clone(),
            inspection,
        });
        report.issue(source.path, "possible_restore_leftover");
    }
}
#[allow(clippy::too_many_arguments)]
fn walk(
    root: &ScanRoot,
    rel: &Path,
    depth: usize,
    source: &ConfigSource,
    budget: Budget,
    attempts: &mut usize,
    visited: &mut Visits,
    report: &mut ScanReport,
    read: &mut impl FnMut(
        &ScanRoot,
        &Path,
        &ConfigSource,
        (File, Metadata),
        &mut usize,
        &mut ScanReport,
    ),
) {
    if depth > 12 {
        report.issue(root.path().join(rel), "too_deep");
        return;
    }
    let dir = if rel.as_os_str().is_empty() {
        root.dir()
            .try_clone()
            .map_err(|_| ScanErrorKind::Unreadable)
    } else {
        root.open_parent(&rel.join("unused")).map(|(d, _)| d)
    };
    let dir = match dir {
        Ok(d) => d,
        Err(e) => {
            report.issue(root.path().join(rel), e.token());
            return;
        }
    };
    if !omitted_kind(source.source_kind) {
        if let Some(omission) = visited.omitted(&root.path().join(rel), true) {
            note_omitted(omission, &root.path().join(rel), report);
            return;
        }
    }
    let entries = match list_dir(&dir, envcloak_sys::MAX_DIR_ENTRIES) {
        Ok(v) => v,
        Err(_) => {
            report.issue(root.path().join(rel), "unreadable");
            return;
        }
    };
    for e in entries {
        if report.issues.iter().any(|i| i.reason == "file_budget") {
            break;
        }
        if *attempts >= budget.files {
            report.issue(root.path().join(rel), "file_budget");
            break;
        }
        let child = rel.join(&e.name);
        if source.names.as_ref().is_some_and(|n| {
            !e.name
                .as_bytes()
                .windows(n.len().max(1))
                .any(|w| w == n.as_bytes())
        }) {
            continue;
        }
        if restore_leftover_name(&e.name) {
            if report
                .leftovers
                .iter()
                .any(|l| l.source.path == root.path().join(&child))
            {
                continue;
            }
            *attempts += 1;
            leftover(root, &child, report);
            continue;
        }
        if e.kind == DirEntryKind::Dir {
            *attempts += 1;
            if source.names.is_none() {
                walk(
                    root,
                    &child,
                    depth + 1,
                    source,
                    budget,
                    attempts,
                    visited,
                    report,
                    read,
                );
            }
        } else {
            process(
                root, &child, source, budget, attempts, visited, report, read, false,
            );
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn process(
    root: &ScanRoot,
    rel: &Path,
    source: &ConfigSource,
    budget: Budget,
    attempts: &mut usize,
    visited: &mut Visits,
    report: &mut ScanReport,
    read: &mut impl FnMut(
        &ScanRoot,
        &Path,
        &ConfigSource,
        (File, Metadata),
        &mut usize,
        &mut ScanReport,
    ),
    optional: bool,
) {
    let path = root.path().join(rel);
    let format = effective_format(rel, source.format);
    if visited.files.get(&path).is_some_and(|state| match state {
        ReadState::Closed => true,
        ReadState::Read(formats) => formats.contains(&format),
    }) {
        return;
    }
    if *attempts >= budget.files {
        report.issue(root.path().join(rel), "file_budget");
        return;
    }
    *attempts += 1;
    if rel.file_name().is_some_and(restore_leftover_name) {
        leftover(root, rel, report);
        visited.files.insert(path, ReadState::Closed);
        return;
    }
    let file = root
        .open_parent(rel)
        .and_then(|(d, n)| crate::root::open_file(&d, &n, usize::MAX));
    let (file, m) = match file {
        Ok(v) => v,
        Err(ScanErrorKind::NotFound) if optional => {
            visited.files.insert(path, ReadState::Closed);
            return;
        }
        Err(e) => {
            visited.files.insert(path, ReadState::Closed);
            report.issue(root.path().join(rel), e.token());
            return;
        }
    };
    if m.dev() != root.dev() {
        visited.files.insert(path, ReadState::Closed);
        report.issue(root.path().join(rel), "mount_point");
        return;
    }
    if m.nlink() > 1 {
        report.issue(root.path().join(rel), "hard_link");
    }
    if !omitted_kind(source.source_kind) {
        if let Some(omission) = visited.omitted(&path, false) {
            note_omitted(omission, &path, report);
            visited.files.insert(path, ReadState::Closed);
            return;
        }
    }
    if note_omitted(source, &root.path().join(rel), report) {
        visited.files.insert(path, ReadState::Closed);
        return;
    }
    if let ReadState::Read(formats) = visited
        .files
        .entry(path)
        .or_insert_with(|| ReadState::Read(Default::default()))
    {
        formats.insert(format);
    }
    let stamp = FileStamp::of(&m);
    let before = report.findings.len();
    read(root, rel, source, (file, m), attempts, report);
    // The reader and discovery share the descriptor and its original stamp.
    for f in &mut report.findings[before..] {
        if stamp.nlink > 1 {
            f.single_complete_line = false;
        }
    }
}

fn note_omitted(source: &ConfigSource, path: &Path, report: &mut ScanReport) -> bool {
    let reason = match source.source_kind {
        SourceKind::Database => "database",
        SourceKind::Credentials => "manual_credentials",
        _ => return false,
    };
    let source = Source {
        path: path.to_path_buf(),
        object: None,
    };
    if !report
        .notes
        .iter()
        .any(|n| n.source == source && n.reason == reason)
    {
        report
            .notes
            .push(crate::candidates::Issue { source, reason });
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn system_aliases_require_root_ownership_and_the_exact_target() {
        for (alias, target) in [
            ("/tmp", "/private/tmp"),
            ("/var", "/private/var"),
            ("/etc", "/private/etc"),
        ] {
            assert_eq!(trusted_alias(alias, 0, Path::new(target)), Some(target));
            assert_eq!(
                trusted_alias(alias, 0, Path::new(&target[1..])),
                Some(target)
            );
            assert!(trusted_alias(alias, 501, Path::new(target)).is_none());
            assert!(trusted_alias(alias, 0, Path::new("/private/elsewhere")).is_none());
            assert!(trusted_alias("/other", 0, Path::new(target)).is_none());
            let root = absolute_root(Path::new(alias)).expect("system directory");
            assert_eq!(root.path(), Path::new(target));
        }
    }

    fn source(path: PathBuf) -> ConfigSource {
        ConfigSource {
            path,
            format: crate::source::ConfigFormat::Raw,
            source_kind: SourceKind::Transcript,
            label: "fixture".into(),
            names: None,
        }
    }

    #[test]
    fn source_leaf_mount_is_refused_before_the_callback() {
        let d = tempfile::tempdir_in("/tmp").expect("fixture");
        std::fs::write(d.path().join("store"), b"fixtureZsourceDeviceValue").expect("write");
        let mut root = crate::open_root(d.path()).expect("root");
        for mounted in [false, true] {
            if mounted {
                root.model_other_device();
            }
            let mut called = false;
            let mut report = ScanReport::default();
            process(
                &root,
                Path::new("store"),
                &source(d.path().join("store")),
                Budget::default(),
                &mut 0,
                &mut Default::default(),
                &mut report,
                &mut |_, _, _, _, _, _| called = true,
                false,
            );
            assert_eq!(called, !mounted);
            assert_eq!(report.complete(), !mounted);
            if mounted {
                assert!(report.issues.iter().any(|i| i.reason == "mount_point"));
            }
        }
    }

    #[test]
    fn failed_source_open_is_charged_and_not_retried() {
        let d = tempfile::tempdir_in("/tmp").expect("fixture");
        let root = crate::open_root(d.path()).expect("root");
        let mut report = ScanReport::default();
        let mut attempts = 0;
        let mut visited = Default::default();
        for _ in 0..2 {
            process(
                &root,
                Path::new("missing"),
                &source(d.path().join("missing")),
                Budget::default(),
                &mut attempts,
                &mut visited,
                &mut report,
                &mut |_, _, _, _, _, _| panic!("missing file was read"),
                false,
            );
        }
        assert_eq!(attempts, 1);
        assert_eq!(visited.files.len(), 1);
        assert!(!report.complete());
    }

    #[test]
    fn leftover_leaf_mount_is_reported_without_reading_contents() {
        let d = tempfile::tempdir_in("/tmp").expect("fixture");
        let name = Path::new(".store.envcloak-new-ab.tmp");
        std::fs::write(d.path().join(name), b"fixtureZleftoverDeviceValue").expect("write");
        let mut root = crate::open_root(d.path()).expect("root");
        for expected in ["possible_leftover", "mount_point"] {
            let mut report = ScanReport::default();
            leftover(&root, name, &mut report);
            assert_eq!(report.leftovers.len(), 1);
            assert_eq!(report.leftovers[0].inspection, expected);
            assert!(!report.complete());
            root.model_other_device();
        }
    }
    #[test]
    fn include_discovery_failure_survives_a_successful_later_read() {
        use std::os::unix::fs::PermissionsExt;
        for state in ["ready", "missing", "unreadable"] {
            let d = tempfile::tempdir_in("/tmp").expect("fixture");
            let root = crate::open_root(d.path()).expect("root");
            let parent = d.path().join("nested");
            if state != "missing" {
                std::fs::create_dir(&parent).expect("parent");
            }
            if state == "unreadable" {
                std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o000))
                    .expect("permissions");
            }
            let mut report = ScanReport::default();
            inspect_include_siblings(
                &root,
                Path::new("nested/values.env"),
                Budget::default(),
                &mut 1,
                &mut report,
            );
            // Deterministic boundary between sibling discovery and include read:
            // the previously missing or unreadable parent becomes readable.
            if state == "missing" {
                std::fs::create_dir(&parent).expect("late parent");
            }
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
                .expect("restore permissions");
            std::fs::write(parent.join("values.env"), b"A=fixtureZlateIncludeParent\n")
                .expect("include");
            let (bytes, _) =
                crate::read_capped(&root, Path::new("nested/values.env"), crate::MAX_DOTENV)
                    .expect("later read succeeds");
            assert!(bytes.ct_eq(b"A=fixtureZlateIncludeParent\n"));
            assert_eq!(
                report.complete(),
                state == "ready",
                "include discovery failure disappeared after parent recovery"
            );
            if state != "ready" {
                let reason = if state == "missing" {
                    "not_found"
                } else {
                    "unreadable"
                };
                assert!(report.issues.iter().any(|i| i.reason == reason));
            }
        }
    }
}
