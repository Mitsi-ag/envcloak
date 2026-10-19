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
    file_ids: std::collections::HashMap<ObjectIdentity, ReadState>,
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

/// Kernel identity of a resolved directory or regular file (`st_dev`, `st_ino`, `st_mode & S_IFMT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectIdentity {
    pub dev: u64,
    pub ino: u64,
    pub kind: u32,
}

impl ObjectIdentity {
    pub fn of(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            #[allow(clippy::unnecessary_cast)]
            kind: m.mode() & (libc::S_IFMT as u32),
        }
    }
}

/// Bounds for no-follow descriptor-relative path resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolveOptions {
    pub max_depth: usize,
    pub max_entries: usize,
    pub check_owner: bool,
    pub check_hard_links: bool,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        Self {
            max_depth: 12,
            max_entries: envcloak_sys::MAX_DIR_ENTRIES,
            check_owner: true,
            check_hard_links: true,
        }
    }
}

/// A path resolved without following user-controlled symlinks, retaining its component chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedObject {
    pub root: PathBuf,
    pub relative: PathBuf,
    pub path: PathBuf,
    pub identity: ObjectIdentity,
    pub chain: Vec<ObjectIdentity>,
    pub stamp: Option<FileStamp>,
    pub nlink: u64,
}

/// Identity witness retained from source selection through the scanner's open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionWitness {
    pub requested: PathBuf,
    pub resolved: PathBuf,
    pub format: ConfigFormat,
    pub requested_chain: Vec<ObjectIdentity>,
    pub resolved_chain: Vec<ObjectIdentity>,
    pub catalog_root: Option<(PathBuf, Vec<ObjectIdentity>)>,
    pub leaf_stamp: Option<FileStamp>,
    pub refusal: Option<&'static str>,
}

fn dir_kind_beneath(dir: &File, name: &std::ffi::OsStr) -> std::io::Result<DirEntryKind> {
    envcloak_sys::kind_beneath(dir, name)
}

fn dir_open_sub(dir: &File, name: &std::ffi::OsStr) -> std::io::Result<File> {
    open_dir_beneath(dir, name)
}

fn dir_open_file(
    dir: &File,
    name: &std::ffi::OsStr,
    max: usize,
) -> Result<(File, Metadata), ScanErrorKind> {
    crate::root::open_file(dir, name, max)
}

fn dir_list(dir: &File, cap: usize) -> std::io::Result<Vec<envcloak_sys::DirEntryName>> {
    list_dir(dir, cap)
}

fn witness_store() -> &'static std::sync::Mutex<std::collections::BTreeMap<u64, SelectionWitness>> {
    static STORE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<u64, SelectionWitness>>,
    > = std::sync::OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

fn record_witness(base_label: &str, w: SelectionWitness) -> String {
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut guard = witness_store().lock().unwrap_or_else(|e| e.into_inner());
    while guard.len() >= 1024 {
        let Some(&first) = guard.keys().next() else {
            break;
        };
        guard.remove(&first);
    }
    guard.insert(id, w);
    let prefix = base_label.split("#ecw").next().unwrap_or(base_label);
    format!("{prefix}#ecw{id}")
}

fn witness_id(source: &ConfigSource) -> Option<u64> {
    source
        .label
        .rsplit_once("#ecw")
        .and_then(|(_, s)| s.parse::<u64>().ok())
}

/// Returns the retained identity witness for a source selected by [`selected_sources`].
pub fn selection_witness(source: &ConfigSource) -> Option<SelectionWitness> {
    let id = witness_id(source)?;
    let guard = witness_store().lock().unwrap_or_else(|e| e.into_inner());
    guard.get(&id).cloned()
}

/// Models an independent `st_dev` change in the retained witness while preserving `st_ino`
/// and `kind`, so device identity is tested separately from inode replacement.
pub fn perturb_witness_device(source: &ConfigSource) -> bool {
    let Some(id) = witness_id(source) else {
        return false;
    };
    let mut guard = witness_store().lock().unwrap_or_else(|e| e.into_inner());
    let Some(w) = guard.get_mut(&id) else {
        return false;
    };
    if let Some(last) = w.resolved_chain.last_mut() {
        last.dev ^= 1;
    }
    if let Some(last) = w.requested_chain.last_mut() {
        last.dev ^= 1;
    }
    if let Some(stamp) = w.leaf_stamp.as_mut() {
        stamp.dev ^= 1;
    }
    true
}

fn open_dir_error(e: &std::io::Error) -> ScanErrorKind {
    if e.raw_os_error() == Some(libc::ENOTDIR) || e.raw_os_error() == Some(libc::ELOOP) {
        ScanErrorKind::Symlink
    } else {
        crate::root::io_kind(e)
    }
}

fn list_dir_error(e: &std::io::Error) -> &'static str {
    if e.kind() == std::io::ErrorKind::OutOfMemory || e.raw_os_error() == Some(libc::EMSGSIZE) {
        "too_many_entries"
    } else {
        "unreadable"
    }
}

fn entry_matches_id(dir: &File, name: &std::ffi::OsStr, target_id: ObjectIdentity) -> bool {
    #[allow(clippy::unnecessary_cast)]
    let is_dir = target_id.kind == (libc::S_IFDIR as u32);
    if is_dir {
        dir_open_sub(dir, name)
            .ok()
            .and_then(|d| d.metadata().ok())
            .is_some_and(|m| ObjectIdentity::of(&m) == target_id)
    } else {
        dir_open_file(dir, name, usize::MAX)
            .ok()
            .is_some_and(|(_, m)| ObjectIdentity::of(&m) == target_id)
    }
}

fn stored_entry_name(
    dir: &File,
    entries: &[envcloak_sys::DirEntryName],
    requested: &std::ffi::OsStr,
    target_id: ObjectIdentity,
) -> Result<std::ffi::OsString, &'static str> {
    let mut matched = Vec::new();
    for e in entries {
        if e.name.as_bytes().eq_ignore_ascii_case(requested.as_bytes())
            && entry_matches_id(dir, &e.name, target_id)
        {
            matched.push(e.name.clone());
        }
    }
    if matched.is_empty() {
        #[allow(clippy::unnecessary_cast)]
        let is_dir = target_id.kind == (libc::S_IFDIR as u32);
        for e in entries {
            let compatible = if is_dir {
                matches!(e.kind, DirEntryKind::Dir | DirEntryKind::Unknown)
            } else {
                matches!(e.kind, DirEntryKind::File | DirEntryKind::Unknown)
            };
            if compatible
                && !e.name.as_bytes().eq_ignore_ascii_case(requested.as_bytes())
                && entry_matches_id(dir, &e.name, target_id)
            {
                matched.push(e.name.clone());
            }
        }
    }
    match matched.len() {
        0 => Err("not_found"),
        1 => Ok(matched.remove(0)),
        _ => Err("hard_link"),
    }
}

/// Resolves `candidate` beneath `root` without following any user-controlled symlink.
pub fn resolve_beneath(
    root: &Path,
    candidate: &Path,
    options: ResolveOptions,
) -> Result<ResolvedObject, &'static str> {
    if !root.is_absolute() || candidate.as_os_str().is_empty() {
        return Err("invalid_path");
    }
    for c in candidate.components() {
        if matches!(c, Component::ParentDir | Component::Prefix(_)) {
            return Err("invalid_path");
        }
    }
    let root_sys = system_path(root).map_err(|e| e.token())?;
    let expected_uid = envcloak_sys::effective_uid();
    let mut cur_dir = File::open("/").map_err(|e| crate::root::io_kind(&e).token())?;
    let slash_meta = cur_dir.metadata().map_err(|_| "unreadable")?;
    let mut root_chain = vec![ObjectIdentity::of(&slash_meta)];
    let mut root_comps = Vec::new();
    for c in root_sys.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                cur_dir = dir_open_sub(&cur_dir, name).map_err(|e| open_dir_error(&e).token())?;
                let m = cur_dir.metadata().map_err(|_| "unreadable")?;
                root_chain.push(ObjectIdentity::of(&m));
                root_comps.push(name.to_os_string());
            }
            _ => return Err("invalid_path"),
        }
    }
    let root_meta = cur_dir.metadata().map_err(|_| "unreadable")?;
    if options.check_owner && root_meta.uid() != expected_uid && root_meta.uid() != 0 {
        return Err("not_owned");
    }
    let root_dev = root_meta.dev();
    let rel_parts: Vec<std::ffi::OsString> = if candidate.is_relative() {
        let mut parts = Vec::new();
        for c in candidate.components() {
            match c {
                Component::CurDir => {}
                Component::Normal(name) => parts.push(name.to_os_string()),
                _ => return Err("invalid_path"),
            }
        }
        parts
    } else {
        let cand_sys = system_path(candidate).map_err(|e| e.token())?;
        let mut cand_comps = Vec::new();
        for c in cand_sys.components() {
            match c {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => cand_comps.push(name.to_os_string()),
                _ => return Err("invalid_path"),
            }
        }
        if cand_comps.len() < root_comps.len() {
            return Err("invalid_path");
        }
        let mut check_dir = File::open("/").map_err(|e| crate::root::io_kind(&e).token())?;
        for (idx, comp) in cand_comps[..root_comps.len()].iter().enumerate() {
            match dir_kind_beneath(&check_dir, comp) {
                Ok(DirEntryKind::Symlink) => return Err("symlink"),
                Ok(DirEntryKind::Dir) => {}
                _ => return Err("invalid_path"),
            }
            check_dir = match dir_open_sub(&check_dir, comp) {
                Ok(d) => d,
                Err(e) => {
                    let kind = open_dir_error(&e);
                    return Err(if kind == ScanErrorKind::Symlink {
                        "symlink"
                    } else {
                        "invalid_path"
                    });
                }
            };
            let m = check_dir.metadata().map_err(|_| "unreadable")?;
            if ObjectIdentity::of(&m) != root_chain[idx + 1] {
                return Err("invalid_path");
            }
        }
        cand_comps[root_comps.len()..].to_vec()
    };

    let root_clean: PathBuf = std::iter::once(Path::new("/"))
        .chain(root_comps.iter().map(Path::new))
        .collect();
    let root_id = *root_chain.last().ok_or("invalid_path")?;
    let mut chain = vec![root_id];
    if rel_parts.is_empty() {
        dir_list(&cur_dir, options.max_entries).map_err(|e| list_dir_error(&e))?;
        return Ok(ResolvedObject {
            root: root_clean.clone(),
            relative: PathBuf::new(),
            path: root_clean,
            identity: root_id,
            chain,
            stamp: None,
            nlink: root_meta.nlink(),
        });
    }

    let mut stored_rel = PathBuf::new();
    for (idx, comp) in rel_parts.iter().enumerate() {
        let depth = idx + 1;
        if depth > options.max_depth {
            return Err("too_deep");
        }
        let entries = dir_list(&cur_dir, options.max_entries).map_err(|e| list_dir_error(&e))?;
        let kind =
            dir_kind_beneath(&cur_dir, comp).map_err(|e| crate::root::io_kind(&e).token())?;
        if kind == DirEntryKind::Symlink {
            return Err("symlink");
        }
        if idx + 1 < rel_parts.len() {
            if kind != DirEntryKind::Dir {
                return Err("not_regular");
            }
            let next_dir = dir_open_sub(&cur_dir, comp).map_err(|e| open_dir_error(&e).token())?;
            let m = next_dir.metadata().map_err(|_| "unreadable")?;
            if m.dev() != root_dev {
                return Err("mount_point");
            }
            if options.check_owner && m.uid() != expected_uid && m.uid() != 0 {
                return Err("not_owned");
            }
            let id = ObjectIdentity::of(&m);
            let stored = stored_entry_name(&cur_dir, &entries, comp, id)?;
            stored_rel.push(stored);
            chain.push(id);
            cur_dir = next_dir;
        } else {
            match kind {
                DirEntryKind::Dir => {
                    let next_dir =
                        dir_open_sub(&cur_dir, comp).map_err(|e| open_dir_error(&e).token())?;
                    let m = next_dir.metadata().map_err(|_| "unreadable")?;
                    if m.dev() != root_dev {
                        return Err("mount_point");
                    }
                    if options.check_owner && m.uid() != expected_uid && m.uid() != 0 {
                        return Err("not_owned");
                    }
                    dir_list(&next_dir, options.max_entries).map_err(|e| list_dir_error(&e))?;
                    let id = ObjectIdentity::of(&m);
                    let stored = stored_entry_name(&cur_dir, &entries, comp, id)?;
                    stored_rel.push(stored);
                    chain.push(id);
                    return Ok(ResolvedObject {
                        path: root_clean.join(&stored_rel),
                        root: root_clean,
                        relative: stored_rel,
                        identity: id,
                        chain,
                        stamp: None,
                        nlink: m.nlink(),
                    });
                }
                DirEntryKind::File => {
                    let (_file, m) =
                        dir_open_file(&cur_dir, comp, usize::MAX).map_err(|e| e.token())?;
                    if m.dev() != root_dev {
                        return Err("mount_point");
                    }
                    if options.check_owner && m.uid() != expected_uid && m.uid() != 0 {
                        return Err("not_owned");
                    }
                    if options.check_hard_links && m.nlink() > 1 {
                        return Err("hard_link");
                    }
                    let id = ObjectIdentity::of(&m);
                    let stored = stored_entry_name(&cur_dir, &entries, comp, id)?;
                    stored_rel.push(stored);
                    chain.push(id);
                    return Ok(ResolvedObject {
                        path: root_clean.join(&stored_rel),
                        root: root_clean,
                        relative: stored_rel,
                        identity: id,
                        chain,
                        stamp: Some(FileStamp::of(&m)),
                        nlink: m.nlink(),
                    });
                }
                DirEntryKind::Symlink => return Err("symlink"),
                DirEntryKind::Other | DirEntryKind::Unknown => return Err("not_regular"),
            }
        }
    }
    Err("invalid_path")
}

#[derive(Debug, Clone)]
struct SlashResolved {
    canonical_path: PathBuf,
    chain: Vec<ObjectIdentity>,
    stored_names: Vec<std::ffi::OsString>,
    is_dir: bool,
    stamp: Option<FileStamp>,
}

fn normal_components(path: &Path) -> Result<Vec<std::ffi::OsString>, &'static str> {
    if !path.is_absolute() {
        return Err("invalid_path");
    }
    let sys = system_path(path).map_err(|e| e.token())?;
    let mut comps = Vec::new();
    for c in sys.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => comps.push(name.to_os_string()),
            _ => return Err("invalid_path"),
        }
    }
    Ok(comps)
}

type CatalogFailure = (Vec<ObjectIdentity>, Option<ObjectIdentity>, &'static str);

fn resolve_catalog_entry(
    path: &Path,
    options: ResolveOptions,
    base_normal_len: usize,
) -> Result<SlashResolved, CatalogFailure> {
    let comps = normal_components(path).map_err(|r| (Vec::new(), None, r))?;
    let expected_uid = envcloak_sys::effective_uid();
    let mut cur_dir =
        File::open("/").map_err(|e| (Vec::new(), None, crate::root::io_kind(&e).token()))?;
    let slash_meta = cur_dir
        .metadata()
        .map_err(|_| (Vec::new(), None, "unreadable"))?;
    let mut chain = vec![ObjectIdentity::of(&slash_meta)];
    let mut stored_names = Vec::with_capacity(comps.len());
    if comps.is_empty() {
        return Ok(SlashResolved {
            canonical_path: PathBuf::from("/"),
            chain,
            stored_names,
            is_dir: true,
            stamp: None,
        });
    }
    for (idx, comp) in comps.iter().enumerate() {
        let kind = dir_kind_beneath(&cur_dir, comp)
            .map_err(|e| (chain.clone(), None, crate::root::io_kind(&e).token()))?;
        if kind == DirEntryKind::Symlink {
            return Err((chain, None, "symlink"));
        }
        if idx + 1 < comps.len() {
            if kind != DirEntryKind::Dir {
                return Err((chain, None, "not_regular"));
            }
            let next_dir = dir_open_sub(&cur_dir, comp)
                .map_err(|e| (chain.clone(), None, open_dir_error(&e).token()))?;
            let m = next_dir
                .metadata()
                .map_err(|_| (chain.clone(), None, "unreadable"))?;
            let id = ObjectIdentity::of(&m);
            if idx + 1 >= base_normal_len
                && options.check_owner
                && m.uid() != expected_uid
                && m.uid() != 0
            {
                return Err((chain, Some(id), "not_owned"));
            }
            let stored = if comp.as_bytes().iter().any(u8::is_ascii_uppercase) {
                if let Ok(list) = dir_list(&cur_dir, envcloak_sys::MAX_DIR_ENTRIES) {
                    stored_entry_name(&cur_dir, &list, comp, id)
                        .map_err(|r| (chain.clone(), Some(id), r))?
                } else {
                    comp.clone()
                }
            } else {
                comp.clone()
            };
            stored_names.push(stored);
            chain.push(id);
            cur_dir = next_dir;
        } else {
            match kind {
                DirEntryKind::Dir => {
                    let next_dir = dir_open_sub(&cur_dir, comp)
                        .map_err(|e| (chain.clone(), None, open_dir_error(&e).token()))?;
                    let m = next_dir
                        .metadata()
                        .map_err(|_| (chain.clone(), None, "unreadable"))?;
                    let id = ObjectIdentity::of(&m);
                    if idx + 1 >= base_normal_len
                        && options.check_owner
                        && m.uid() != expected_uid
                        && m.uid() != 0
                    {
                        return Err((chain, Some(id), "not_owned"));
                    }
                    let stored = if let Ok(list) = dir_list(&cur_dir, envcloak_sys::MAX_DIR_ENTRIES)
                    {
                        stored_entry_name(&cur_dir, &list, comp, id)
                            .map_err(|r| (chain.clone(), Some(id), r))?
                    } else {
                        comp.clone()
                    };
                    stored_names.push(stored);
                    chain.push(id);
                    let canonical_path: PathBuf = std::iter::once(Path::new("/"))
                        .chain(stored_names.iter().map(Path::new))
                        .collect();
                    return Ok(SlashResolved {
                        canonical_path,
                        chain,
                        stored_names,
                        is_dir: true,
                        stamp: None,
                    });
                }
                DirEntryKind::File => {
                    let (_file, m) = dir_open_file(&cur_dir, comp, usize::MAX)
                        .map_err(|e| (chain.clone(), None, e.token()))?;
                    let id = ObjectIdentity::of(&m);
                    if options.check_owner && m.uid() != expected_uid && m.uid() != 0 {
                        return Err((chain, Some(id), "not_owned"));
                    }
                    if options.check_hard_links && m.nlink() > 1 {
                        return Err((chain, Some(id), "hard_link"));
                    }
                    let stored = if let Ok(list) = dir_list(&cur_dir, envcloak_sys::MAX_DIR_ENTRIES)
                    {
                        stored_entry_name(&cur_dir, &list, comp, id)
                            .map_err(|r| (chain.clone(), Some(id), r))?
                    } else {
                        comp.clone()
                    };
                    stored_names.push(stored);
                    chain.push(id);
                    let canonical_path: PathBuf = std::iter::once(Path::new("/"))
                        .chain(stored_names.iter().map(Path::new))
                        .collect();
                    return Ok(SlashResolved {
                        canonical_path,
                        chain,
                        stored_names,
                        is_dir: false,
                        stamp: Some(FileStamp::of(&m)),
                    });
                }
                DirEntryKind::Symlink => return Err((chain, None, "symlink")),
                DirEntryKind::Other | DirEntryKind::Unknown => {
                    return Err((chain, None, "not_regular"));
                }
            }
        }
    }
    Err((chain, None, "invalid_path"))
}

fn resolve_selected_path(
    path: &Path,
    options: ResolveOptions,
    base_normal_len: usize,
) -> Result<SlashResolved, &'static str> {
    let comps = normal_components(path)?;
    if comps.len().saturating_sub(base_normal_len) > options.max_depth {
        return Err("too_deep");
    }
    let expected_uid = envcloak_sys::effective_uid();
    let mut cur_dir = File::open("/").map_err(|e| crate::root::io_kind(&e).token())?;
    let slash_meta = cur_dir.metadata().map_err(|_| "unreadable")?;
    let mut chain = vec![ObjectIdentity::of(&slash_meta)];
    let mut stored_names = Vec::with_capacity(comps.len());
    if comps.is_empty() {
        return Ok(SlashResolved {
            canonical_path: PathBuf::from("/"),
            chain,
            stored_names,
            is_dir: true,
            stamp: None,
        });
    }
    let mut anchor_dev = if base_normal_len == 0 {
        Some(slash_meta.dev())
    } else {
        None
    };
    for (idx, comp) in comps.iter().enumerate() {
        let kind =
            dir_kind_beneath(&cur_dir, comp).map_err(|e| crate::root::io_kind(&e).token())?;
        if kind == DirEntryKind::Symlink {
            return Err("symlink");
        }
        let should_list = idx >= base_normal_len
            || idx + 1 == comps.len()
            || comp.as_bytes().iter().any(u8::is_ascii_uppercase);
        let list_cap = if idx >= base_normal_len {
            options.max_entries
        } else {
            envcloak_sys::MAX_DIR_ENTRIES
        };
        let entries = if should_list {
            Some(dir_list(&cur_dir, list_cap).map_err(|e| list_dir_error(&e))?)
        } else {
            None
        };
        if idx + 1 < comps.len() {
            if kind != DirEntryKind::Dir {
                return Err("not_regular");
            }
            let next_dir = dir_open_sub(&cur_dir, comp).map_err(|e| open_dir_error(&e).token())?;
            let m = next_dir.metadata().map_err(|_| "unreadable")?;
            if let Some(dev) = anchor_dev {
                if m.dev() != dev {
                    return Err("mount_point");
                }
            } else if idx + 1 >= base_normal_len {
                anchor_dev = Some(m.dev());
            }
            if idx + 1 >= base_normal_len
                && options.check_owner
                && m.uid() != expected_uid
                && m.uid() != 0
            {
                return Err("not_owned");
            }
            let id = ObjectIdentity::of(&m);
            let stored = if let Some(ref list) = entries {
                stored_entry_name(&cur_dir, list, comp, id)?
            } else {
                comp.clone()
            };
            stored_names.push(stored);
            chain.push(id);
            cur_dir = next_dir;
        } else {
            match kind {
                DirEntryKind::Dir => {
                    let next_dir =
                        dir_open_sub(&cur_dir, comp).map_err(|e| open_dir_error(&e).token())?;
                    let m = next_dir.metadata().map_err(|_| "unreadable")?;
                    if let Some(dev) = anchor_dev {
                        if m.dev() != dev {
                            return Err("mount_point");
                        }
                    }
                    if idx + 1 >= base_normal_len
                        && options.check_owner
                        && m.uid() != expected_uid
                        && m.uid() != 0
                    {
                        return Err("not_owned");
                    }
                    dir_list(&next_dir, options.max_entries).map_err(|e| list_dir_error(&e))?;
                    let id = ObjectIdentity::of(&m);
                    let stored = if let Some(ref list) = entries {
                        stored_entry_name(&cur_dir, list, comp, id)?
                    } else {
                        comp.clone()
                    };
                    stored_names.push(stored);
                    chain.push(id);
                    let canonical_path: PathBuf = std::iter::once(Path::new("/"))
                        .chain(stored_names.iter().map(Path::new))
                        .collect();
                    return Ok(SlashResolved {
                        canonical_path,
                        chain,
                        stored_names,
                        is_dir: true,
                        stamp: None,
                    });
                }
                DirEntryKind::File => {
                    let (_file, m) =
                        dir_open_file(&cur_dir, comp, usize::MAX).map_err(|e| e.token())?;
                    if let Some(dev) = anchor_dev {
                        if m.dev() != dev {
                            return Err("mount_point");
                        }
                    }
                    if options.check_owner && m.uid() != expected_uid && m.uid() != 0 {
                        return Err("not_owned");
                    }
                    if options.check_hard_links && m.nlink() > 1 {
                        return Err("hard_link");
                    }
                    let id = ObjectIdentity::of(&m);
                    let stored = if let Some(ref list) = entries {
                        stored_entry_name(&cur_dir, list, comp, id)?
                    } else {
                        comp.clone()
                    };
                    stored_names.push(stored);
                    chain.push(id);
                    let canonical_path: PathBuf = std::iter::once(Path::new("/"))
                        .chain(stored_names.iter().map(Path::new))
                        .collect();
                    return Ok(SlashResolved {
                        canonical_path,
                        chain,
                        stored_names,
                        is_dir: false,
                        stamp: Some(FileStamp::of(&m)),
                    });
                }
                DirEntryKind::Symlink => return Err("symlink"),
                DirEntryKind::Other | DirEntryKind::Unknown => return Err("not_regular"),
            }
        }
    }
    Err("invalid_path")
}

/// Resolves a user-selected scrub path against the catalog using kernel object identity
/// (`st_dev`, `st_ino`, `st_mode & S_IFMT`) rather than raw path strings.
pub fn selected_sources(path: PathBuf, catalog: &[ConfigSource]) -> Vec<ConfigSource> {
    select_sources_with_options(path, catalog, ResolveOptions::default())
}

/// Resolves a user-selected scrub path against the catalog with explicit resolution bounds.
pub fn select_sources_with_options(
    path: PathBuf,
    catalog: &[ConfigSource],
    options: ResolveOptions,
) -> Vec<ConfigSource> {
    let path_comps = normal_components(&path).unwrap_or_default();
    let sys_tmp_len = if path_comps.len() >= 2
        && path_comps[0].as_bytes().eq_ignore_ascii_case(b"private")
        && path_comps[1].as_bytes().eq_ignore_ascii_case(b"tmp")
    {
        2
    } else if !path_comps.is_empty() && path_comps[0].as_bytes().eq_ignore_ascii_case(b"tmp") {
        1
    } else {
        0
    };
    let related_anchor = catalog
        .iter()
        .filter_map(|s| {
            let s_comps = normal_components(&s.path).ok()?;
            let lcp = path_comps
                .iter()
                .zip(s_comps.iter())
                .take_while(|(a, b)| a.as_bytes().eq_ignore_ascii_case(b.as_bytes()))
                .count();
            if lcp <= sys_tmp_len {
                return None;
            }
            let s_anchor = if s.names.is_some() {
                s_comps.len()
            } else {
                s_comps.len().saturating_sub(1)
            };
            Some(lcp.min(s_anchor))
        })
        .min();
    let base_normal_len = related_anchor.unwrap_or_else(|| {
        if sys_tmp_len > 0 && path_comps.len() > sys_tmp_len {
            (sys_tmp_len + 1).min(path_comps.len().saturating_sub(1))
        } else {
            path_comps.len().saturating_sub(1).clamp(1, 2)
        }
    });

    let mut resolved_catalog: Vec<(ConfigSource, SlashResolved)> = Vec::new();
    let mut catalog_failures: Vec<(Option<String>, CatalogFailure)> = Vec::new();
    for s in catalog {
        match resolve_catalog_entry(&s.path, options, base_normal_len) {
            Ok(res) => {
                let mut clean = s.clone();
                let sys = system_path(&s.path).unwrap_or_else(|_| s.path.clone());
                clean.path = sys.components().collect();
                resolved_catalog.push((clean, res));
            }
            Err((_, _, "not_found")) => {}
            Err(fail) => {
                if !omitted_kind(s.source_kind) {
                    catalog_failures.push((s.names.clone(), fail));
                }
            }
        }
    }

    let sel = match resolve_selected_path(&path, options, base_normal_len) {
        Ok(res) => res,
        Err(reason) => {
            let norm = system_path(&path).unwrap_or_else(|_| path.clone());
            let label = record_witness(
                "scrub path",
                SelectionWitness {
                    requested: path,
                    resolved: norm.clone(),
                    format: ConfigFormat::Raw,
                    requested_chain: Vec::new(),
                    resolved_chain: Vec::new(),
                    catalog_root: None,
                    leaf_stamp: None,
                    refusal: Some(reason),
                },
            );
            return vec![ConfigSource {
                path: norm,
                format: ConfigFormat::Raw,
                source_kind: SourceKind::Transcript,
                label,
                names: None,
            }];
        }
    };

    let relevant_refusal =
        catalog_failures
            .iter()
            .find_map(|(s_names, (partial_chain, failed_id, reason))| {
                if let Some(id) = failed_id {
                    let mut fail_chain = partial_chain.clone();
                    fail_chain.push(*id);
                    if let Some(pattern) = s_names {
                        if sel.is_dir && fail_chain.starts_with(&sel.chain) {
                            return Some(*reason);
                        }
                        if !sel.is_dir
                            && sel.chain.len() == fail_chain.len() + 1
                            && sel.chain.starts_with(&fail_chain)
                            && sel.stored_names.last().is_some_and(|n| {
                                n.as_bytes()
                                    .windows(pattern.len().max(1))
                                    .any(|w| w == pattern.as_bytes())
                            })
                        {
                            return Some(*reason);
                        }
                        None
                    } else if sel.chain.starts_with(&fail_chain)
                        || (sel.is_dir && fail_chain.starts_with(&sel.chain))
                    {
                        Some(*reason)
                    } else {
                        None
                    }
                } else if sel.is_dir && partial_chain.starts_with(&sel.chain) {
                    Some(*reason)
                } else {
                    None
                }
            });

    if let Some(reason) = relevant_refusal {
        let label = record_witness(
            "scrub path",
            SelectionWitness {
                requested: path,
                resolved: sel.canonical_path.clone(),
                format: ConfigFormat::Raw,
                requested_chain: sel.chain.clone(),
                resolved_chain: sel.chain,
                catalog_root: None,
                leaf_stamp: sel.stamp,
                refusal: Some(reason),
            },
        );
        return vec![ConfigSource {
            path: sel.canonical_path,
            format: ConfigFormat::Raw,
            source_kind: SourceKind::Transcript,
            label,
            names: None,
        }];
    }

    // Named sources select direct file children only, never the enclosing directory.
    // A known store's grammar wins over an arbitrary file extension.
    let enclosing = resolved_catalog
        .iter()
        .filter(|(s, s_res)| match &s.names {
            Some(name) => {
                !sel.is_dir
                    && sel.chain.len() == s_res.chain.len() + 1
                    && sel.chain[..s_res.chain.len()] == s_res.chain[..]
                    && sel.stored_names.last().is_some_and(|n| {
                        n.as_bytes()
                            .windows(name.len().max(1))
                            .any(|w| w == name.as_bytes())
                    })
            }
            None => {
                sel.chain.len() >= s_res.chain.len()
                    && sel.chain[..s_res.chain.len()] == s_res.chain[..]
            }
        })
        .max_by_key(|(_, s_res)| s_res.chain.len());

    if let Some((_, s_res)) = enclosing {
        if let Some(&cat_root_id) = s_res.chain.last() {
            if sel.chain[s_res.chain.len().saturating_sub(1)..]
                .iter()
                .any(|id| id.dev != cat_root_id.dev)
            {
                let label = record_witness(
                    "scrub path",
                    SelectionWitness {
                        requested: path,
                        resolved: sel.canonical_path.clone(),
                        format: ConfigFormat::Raw,
                        requested_chain: sel.chain.clone(),
                        resolved_chain: sel.chain,
                        catalog_root: None,
                        leaf_stamp: sel.stamp,
                        refusal: Some("mount_point"),
                    },
                );
                return vec![ConfigSource {
                    path: sel.canonical_path,
                    format: ConfigFormat::Raw,
                    source_kind: SourceKind::Transcript,
                    label,
                    names: None,
                }];
            }
        }
    }

    let format = enclosing.map_or_else(
        || {
            if sel.is_dir {
                ConfigFormat::Mixed
            } else if sel.canonical_path.extension().is_some_and(|e| e == "json") {
                ConfigFormat::Json
            } else {
                ConfigFormat::Mixed
            }
        },
        |(s, _)| s.format,
    );

    let source_kind = enclosing.map_or(SourceKind::Transcript, |(s, _)| {
        if omitted_kind(s.source_kind) {
            s.source_kind
        } else {
            SourceKind::Transcript
        }
    });

    let resolved_path = if let Some((s, s_res)) = enclosing {
        let cat_comps = s_res.chain.len().saturating_sub(1);
        let mut p = s.path.clone();
        for name in sel.stored_names.iter().skip(cat_comps) {
            p.push(name);
        }
        p
    } else {
        sel.canonical_path.clone()
    };

    let mut selected = Vec::new();
    for (s, s_res) in &resolved_catalog {
        if s_res.chain.len() >= sel.chain.len() && s_res.chain[..sel.chain.len()] == sel.chain[..] {
            let mut sub = s.clone();
            if s_res.chain.len() > sel.chain.len() {
                let mut canonical_sub = resolved_path.clone();
                for name in s_res.stored_names.iter().skip(sel.stored_names.len()) {
                    canonical_sub.push(name);
                }
                sub.path = canonical_sub;
            } else {
                sub.path = resolved_path.clone();
            }
            sub.label = record_witness(
                &s.label,
                SelectionWitness {
                    requested: s.path.clone(),
                    resolved: sub.path.clone(),
                    format: s.format,
                    requested_chain: s_res.chain.clone(),
                    resolved_chain: s_res.chain.clone(),
                    catalog_root: Some((s.path.clone(), s_res.chain.clone())),
                    leaf_stamp: s_res.stamp,
                    refusal: None,
                },
            );
            selected.push(sub);
        }
    }

    let catalog_root = enclosing.map(|(s, s_res)| (s.path.clone(), s_res.chain.clone()));

    let label = record_witness(
        "scrub path",
        SelectionWitness {
            requested: path,
            resolved: resolved_path.clone(),
            format,
            requested_chain: sel.chain.clone(),
            resolved_chain: sel.chain,
            catalog_root,
            leaf_stamp: sel.stamp,
            refusal: None,
        },
    );

    selected.retain(|s| {
        !(s.path == resolved_path
            && s.names.is_none()
            && s.format == format
            && s.source_kind == source_kind)
    });
    selected.push(ConfigSource {
        path: resolved_path,
        format,
        source_kind,
        label,
        names: None,
    });
    selected
}

fn verify_chain(
    path: &Path,
    expected: &[ObjectIdentity],
) -> Result<Option<FileStamp>, &'static str> {
    let comps = normal_components(path)?;
    if comps.len() + 1 != expected.len() {
        return Err("changed");
    }
    let mut cur_dir = File::open("/").map_err(|_| "unreadable")?;
    let slash_meta = cur_dir.metadata().map_err(|_| "unreadable")?;
    if ObjectIdentity::of(&slash_meta) != expected[0] {
        return Err("changed");
    }
    for (idx, comp) in comps.iter().enumerate() {
        let target_id = expected[idx + 1];
        let kind = match dir_kind_beneath(&cur_dir, comp) {
            Ok(k) => k,
            Err(_) => return Err("changed"),
        };
        if kind == DirEntryKind::Symlink {
            return Err("symlink");
        }
        if idx + 1 < comps.len() {
            if kind != DirEntryKind::Dir {
                return Err("changed");
            }
            let next_dir = match dir_open_sub(&cur_dir, comp) {
                Ok(d) => d,
                Err(e) => {
                    return Err(if open_dir_error(&e) == ScanErrorKind::Symlink {
                        "symlink"
                    } else {
                        "changed"
                    });
                }
            };
            let m = next_dir.metadata().map_err(|_| "unreadable")?;
            if ObjectIdentity::of(&m) != target_id {
                return Err("changed");
            }
            cur_dir = next_dir;
        } else {
            #[allow(clippy::unnecessary_cast)]
            let want_dir = target_id.kind == (libc::S_IFDIR as u32);
            if want_dir {
                if kind != DirEntryKind::Dir {
                    return Err("changed");
                }
                let next_dir = match dir_open_sub(&cur_dir, comp) {
                    Ok(d) => d,
                    Err(e) => {
                        return Err(if open_dir_error(&e) == ScanErrorKind::Symlink {
                            "symlink"
                        } else {
                            "changed"
                        });
                    }
                };
                let m = next_dir.metadata().map_err(|_| "unreadable")?;
                if ObjectIdentity::of(&m) != target_id {
                    return Err("changed");
                }
                return Ok(None);
            } else {
                if kind != DirEntryKind::File {
                    return Err("changed");
                }
                let (_file, m) = match dir_open_file(&cur_dir, comp, usize::MAX) {
                    Ok(v) => v,
                    Err(ScanErrorKind::Symlink) => return Err("symlink"),
                    Err(_) => return Err("changed"),
                };
                if ObjectIdentity::of(&m) != target_id {
                    return Err("changed");
                }
                return Ok(Some(FileStamp::of(&m)));
            }
        }
    }
    Ok(None)
}

fn verify_witness(w: &SelectionWitness) -> Result<(), &'static str> {
    if let Some(reason) = w.refusal {
        return Err(reason);
    }
    if let Some((ref cat_path, ref cat_chain)) = w.catalog_root {
        verify_chain(cat_path, cat_chain)?;
    }
    if !w.requested_chain.is_empty() && w.requested != w.resolved {
        let req_stamp = verify_chain(&w.requested, &w.requested_chain)?;
        if w.leaf_stamp.is_some() && req_stamp != w.leaf_stamp {
            return Err("changed");
        }
    }
    let res_stamp = verify_chain(&w.resolved, &w.resolved_chain)?;
    if w.leaf_stamp.is_some() && res_stamp != w.leaf_stamp {
        return Err("changed");
    }
    Ok(())
}

/// Opens a catalog-selected or sealed restore directory without following any user-controlled
/// component. Only root-owned, fixed-target macOS system aliases are resolved.
pub fn absolute_root(path: &Path) -> Result<ScanRoot, ScanErrorKind> {
    if !path.is_absolute() {
        return Err(ScanErrorKind::InvalidPath);
    }
    let path = system_path(path)?;
    let mut dir = File::open("/").map_err(|e| crate::root::io_kind(&e))?;
    let mut clean = PathBuf::from("/");
    for c in path.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                dir = dir_open_sub(&dir, name).map_err(|e| open_dir_error(&e))?;
                clean.push(name);
            }
            _ => return Err(ScanErrorKind::InvalidPath),
        }
    }
    crate::root::held_root(clean, dir).map_err(|e| crate::root::io_kind(&e))
}

/// Uses the same fixed, root-owned system aliases as source discovery.
/// Does not resolve any user-controlled path component.
pub fn system_path(path: &Path) -> Result<PathBuf, ScanErrorKind> {
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

pub(crate) fn walk_sources_leftovers(
    sources: &[ConfigSource],
    budget: Budget,
    report: &mut ScanReport,
) {
    walk_sources_inner(sources, budget, report, false, |_, _, _, _, _, _| {});
}

pub(crate) fn walk_sources(
    sources: &[ConfigSource],
    budget: Budget,
    report: &mut ScanReport,
    read: impl FnMut(&ScanRoot, &Path, &ConfigSource, (File, Metadata), &mut usize, &mut ScanReport),
) {
    walk_sources_inner(sources, budget, report, true, read);
}

fn walk_sources_inner(
    sources: &[ConfigSource],
    budget: Budget,
    report: &mut ScanReport,
    check_witness: bool,
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
    if check_witness {
        for source in sources {
            if let Some(w) = selection_witness(source) {
                if let Err(reason) = verify_witness(&w) {
                    attempts += 1;
                    if reason == "not_found" {
                        if let (Some(parent), Some(name)) =
                            (source.path.parent(), source.path.file_name())
                        {
                            if let Ok(root) = absolute_root(parent) {
                                inspect_siblings(&root, Some(name), budget, &mut attempts, report);
                            }
                        }
                    }
                    failed_roots.insert(source.path.clone());
                    report.issue(&source.path, reason);
                }
            }
        }
        if !failed_roots.is_empty() {
            return;
        }
    }
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
        let witness = if check_witness {
            selection_witness(source)
        } else {
            None
        };
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
        match dir_kind_beneath(root.dir(), name) {
            Ok(DirEntryKind::Dir) => {
                attempts += 1;
                let dir = match dir_open_sub(root.dir(), name) {
                    Ok(d) => d,
                    Err(e) => {
                        failed_roots.insert(source.path.clone());
                        report.issue(&source.path, open_dir_error(&e).token());
                        continue;
                    }
                };
                if let Some(ref w) = witness {
                    let ok = dir.metadata().ok().is_some_and(|m| {
                        w.resolved_chain.last().copied() == Some(ObjectIdentity::of(&m))
                    });
                    if !ok {
                        failed_roots.insert(source.path.clone());
                        report.issue(&source.path, "changed");
                        continue;
                    }
                }
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
                    witness.as_ref(),
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
    match dir_list(root.dir(), envcloak_sys::MAX_DIR_ENTRIES) {
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
        .and_then(|(d, n)| dir_open_file(&d, &n, crate::MAX_DOTENV))
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
    let entries = match dir_list(&dir, envcloak_sys::MAX_DIR_ENTRIES) {
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
                root, &child, source, None, budget, attempts, visited, report, read, false,
            );
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn process(
    root: &ScanRoot,
    rel: &Path,
    source: &ConfigSource,
    witness: Option<&SelectionWitness>,
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
        .and_then(|(d, n)| dir_open_file(&d, &n, usize::MAX));
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
    let actual_id = ObjectIdentity::of(&m);
    if let Some(w) = witness {
        let actual_stamp = FileStamp::of(&m);
        if w.resolved_chain.last().copied() != Some(actual_id)
            || w.leaf_stamp.is_some_and(|s| s != actual_stamp)
        {
            visited.files.insert(path, ReadState::Closed);
            visited.file_ids.insert(actual_id, ReadState::Closed);
            report.issue(root.path().join(rel), "changed");
            return;
        }
    }
    if visited
        .file_ids
        .get(&actual_id)
        .is_some_and(|state| match state {
            ReadState::Closed => true,
            ReadState::Read(formats) => m.nlink() == 1 && formats.contains(&format),
        })
    {
        return;
    }
    if m.nlink() > 1 {
        report.issue(root.path().join(rel), "hard_link");
    }
    if !omitted_kind(source.source_kind) {
        if let Some(omission) = visited.omitted(&path, false) {
            note_omitted(omission, &path, report);
            visited.files.insert(path, ReadState::Closed);
            visited.file_ids.insert(actual_id, ReadState::Closed);
            return;
        }
    }
    if note_omitted(source, &root.path().join(rel), report) {
        visited.files.insert(path, ReadState::Closed);
        visited.file_ids.insert(actual_id, ReadState::Closed);
        return;
    }
    if let ReadState::Read(formats) = visited
        .files
        .entry(path)
        .or_insert_with(|| ReadState::Read(Default::default()))
    {
        formats.insert(format);
    }
    if let ReadState::Read(formats) = visited
        .file_ids
        .entry(actual_id)
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
                None,
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
                None,
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
