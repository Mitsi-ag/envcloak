//! Descriptor-relative discovery shared by configs and transcript stores.
use crate::candidates::{Budget, Leftover, ScanReport, Source};
use crate::source::{ConfigSource, SourceKind};
use crate::{FileStamp, ScanErrorKind, ScanRoot};
use envcloak_sys::{DirEntryKind, list_dir, open_dir_beneath};
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Opens a catalog-selected directory without following any user-controlled
/// component. The system's /tmp alias on macOS is resolved before walking.
pub(crate) fn absolute_root(path: &Path) -> Result<ScanRoot, ScanErrorKind> {
    if !path.is_absolute() {
        return Err(ScanErrorKind::InvalidPath);
    }
    let path = if let Ok(rest) = path.strip_prefix("/tmp") {
        std::fs::canonicalize("/tmp")
            .map_err(|e| crate::root::io_kind(&e))?
            .join(rest)
    } else {
        path.to_path_buf()
    };
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

/// A strict name shape, not ownership evidence. Includes interrupted restore
/// staging and displaced swap files beside non-env files.
pub fn restore_leftover_name(name: &std::ffi::OsStr) -> bool {
    let b = name.as_bytes();
    if !b.starts_with(b".") {
        return false;
    }
    for tag in [b".envcloak-new-".as_slice(), b".envcloak-swap-"] {
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
    mut read: impl FnMut(&ScanRoot, &Path, &ConfigSource, &mut ScanReport),
) {
    let mut visited = std::collections::HashSet::new();
    let mut attempts = 0usize;
    for source in sources {
        if source.source_kind == SourceKind::Database {
            report.issue(&source.path, "database");
            continue;
        }
        if source.source_kind == SourceKind::Credentials {
            report.issue(&source.path, "manual_credentials");
            continue;
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
            Err(ScanErrorKind::NotFound) => continue,
            Err(e) => {
                report.issue(&source.path, e.token());
                continue;
            }
        };
        match envcloak_sys::kind_beneath(root.dir(), name) {
            Ok(DirEntryKind::Dir) => {
                let dir = match root.open_subdir(root.dir(), name) {
                    Ok(d) => d,
                    Err(e) => {
                        report.issue(&source.path, e.token());
                        continue;
                    }
                };
                let sub = match crate::root::held_root(root.path().join(name), dir) {
                    Ok(r) => r,
                    Err(_) => {
                        report.issue(&source.path, "io");
                        continue;
                    }
                };
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
fn leftover(root: &ScanRoot, rel: &Path, report: &mut ScanReport) {
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
    visited: &mut std::collections::HashSet<PathBuf>,
    report: &mut ScanReport,
    read: &mut impl FnMut(&ScanRoot, &Path, &ConfigSource, &mut ScanReport),
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
    let entries = match list_dir(&dir, envcloak_sys::MAX_DIR_ENTRIES) {
        Ok(v) => v,
        Err(_) => {
            report.issue(root.path().join(rel), "unreadable");
            return;
        }
    };
    for e in entries {
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
    visited: &mut std::collections::HashSet<PathBuf>,
    report: &mut ScanReport,
    read: &mut impl FnMut(&ScanRoot, &Path, &ConfigSource, &mut ScanReport),
    optional: bool,
) {
    if *attempts >= budget.files {
        report.issue(root.path().join(rel), "file_budget");
        return;
    }
    let file = root
        .open_parent(rel)
        .and_then(|(d, n)| crate::root::open_file(&d, &n, usize::MAX));
    let (_, m) = match file {
        Ok(v) => v,
        Err(ScanErrorKind::NotFound) if optional => return,
        Err(e) => {
            *attempts += 1;
            report.issue(root.path().join(rel), e.token());
            return;
        }
    };
    *attempts += 1;
    if m.dev() != root.dev() {
        report.issue(root.path().join(rel), "mount_point");
        return;
    }
    if m.nlink() > 1 {
        report.issue(root.path().join(rel), "hard_link");
    }
    if !visited.insert(root.path().join(rel)) {
        return;
    }
    let stamp = FileStamp::of(&m);
    let before = report.findings.len();
    read(root, rel, source, report);
    // Parsers' stamps belong to their own descriptor read, not this walk.
    for f in &mut report.findings[before..] {
        if stamp.nlink > 1 {
            f.single_complete_line = false;
        }
    }
}
