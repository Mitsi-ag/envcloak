//! Finding dotenv files under a [`ScanRoot`] (SPEC §6.4 "Filesystem
//! safety").
//!
//! [`walk_dotenv`] lists the root, and with [`WalkOptions::recursive`] the
//! directories below it, through directory handles:
//! - a directory symlink is never followed, so a symlink loop ends nothing
//!   and nothing outside the root is reached; a directory reached twice
//!   (a bind mount, a hard-linked directory) is listed once;
//! - a mount point is not crossed, so a network or cloud volume mounted
//!   inside the tree is not entered (a root on one, named explicitly, is
//!   scanned);
//! - the directories in [`WalkOptions::skip_dirs`] are not entered
//!   (version control, dependency and cache directories, and the folders
//!   macOS keeps cloud-provider files in);
//! - a directory with more than [`envcloak_sys::MAX_DIR_ENTRIES`] entries
//!   is reported and not listed, and the walk stops at
//!   [`WalkOptions::max_depth`] and [`WalkOptions::max_files`];
//! - only the directories on the path down to the one being listed are
//!   open: a subdirectory waits by name, and is opened beneath its parent
//!   when its turn comes, so a tree of hundreds of sibling projects never
//!   runs the process out of descriptors (macOS allows 256 by default).
//!
//! A file an interrupted change of an env file left under a temporary name
//! (`.<name>.envcloak-<new|swap|del>-<hex>.tmp`, see [`crate::atomic`]) is
//! reported as [`ScanErrorKind::Leftover`]: it may hold plaintext, and no
//! `.gitignore` line for the env file covers it.
//!
//! Each file named `.env` or `.env.<suffix>` is opened as
//! [`crate::read_capped`] opens one, never through a symlink and never
//! waiting on a FIFO, and reported as a [`FoundFile`] when it is a regular
//! file of this user of at most [`crate::MAX_DOTENV`] bytes, or as a
//! [`ScanError`] saying why not. Nothing is read here: the caller reads
//! what it wants with [`crate::read_capped`]. A file with another hard
//! link is found, and flagged, since it is never modified.
//!
//! `.env` is the default profile and `.env.<name>` the profile `<name>`
//! (lowercased, with `.` read as `-`: `.env.development.local` is
//! `development-local`). The template names `.env.example`,
//! `.env.sample`, `.env.template` and `.env.dist` hold names, not values:
//! [`FileKind::Template`], and so does a name with one of those among its
//! dot-separated parts (`.env.local.example`, `.env.example.local`).

use std::collections::{HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use envcloak_policy::ProfileName;
use envcloak_sys::{DirEntryKind, MAX_DIR_ENTRIES, list_dir};

use crate::dotenv::MAX_DOTENV;
use crate::root::{ScanError, ScanErrorKind, ScanRoot, open_file};

/// The suffixes of template files, which contribute names only.
pub const TEMPLATE_SUFFIXES: [&str; 4] = ["example", "sample", "template", "dist"];

/// Directory names a walk never enters.
pub const DEFAULT_SKIP_DIRS: [&str; 19] = [
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".gradle",
    ".cache",
    ".npm",
    ".cargo",
    ".rustup",
    ".Trash",
    // macOS: File Provider cloud storage and iCloud Drive.
    "CloudStorage",
    "Mobile Documents",
];

/// How far a walk goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkOptions {
    /// List the directories below the root too.
    pub recursive: bool,
    /// Levels of directories below the root that are listed.
    pub max_depth: usize,
    /// The walk stops after finding this many files.
    pub max_files: usize,
    /// The walk stops after visiting this many directories, including the root.
    pub max_dirs: usize,
    /// Directory names never entered.
    pub skip_dirs: Vec<OsString>,
}

impl Default for WalkOptions {
    fn default() -> Self {
        WalkOptions {
            recursive: false,
            max_depth: 12,
            max_files: 10_000,
            max_dirs: 10_000,
            skip_dirs: DEFAULT_SKIP_DIRS.iter().map(OsString::from).collect(),
        }
    }
}

/// What a dotenv file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileKind {
    /// Values: `.env` (`profile` `None`) or `.env.<profile>`.
    Dotenv { profile: Option<ProfileName> },
    /// Names only: `.env.example` and the like.
    Template,
}

/// A dotenv file a walk found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundFile {
    /// Relative to the root.
    pub rel: PathBuf,
    pub kind: FileKind,
    pub size: u64,
    /// Another hard link names it too: it is read, and never modified.
    pub hard_linked: bool,
}

/// Whether `name` is a dotenv file's, and what it holds. `Some(Err(()))`
/// for `.env.<suffix>` whose suffix makes no profile name.
pub fn dotenv_kind(name: &OsStr) -> Option<Result<FileKind, ()>> {
    let b = name.as_bytes();
    if b == b".env" {
        return Some(Ok(FileKind::Dotenv { profile: None }));
    }
    let suffix = b.strip_prefix(b".env.")?;
    let suffix = std::str::from_utf8(suffix)
        .ok()
        .map(str::to_ascii_lowercase);
    let Some(suffix) = suffix.filter(|s| !s.is_empty()) else {
        return Some(Err(()));
    };
    // `.env.local.example`, `.env.example.local`: a template too.
    if suffix
        .split('.')
        .any(|part| TEMPLATE_SUFFIXES.contains(&part))
    {
        return Some(Ok(FileKind::Template));
    }
    Some(
        ProfileName::new(&suffix.replace('.', "-"))
            .map(|p| FileKind::Dotenv { profile: Some(p) })
            .map_err(|_| ()),
    )
}

/// Whether `name` is a temporary name a change of an env file uses
/// (`.<name>.envcloak-<what>-<hex>.tmp`, the name left out when long).
pub fn leftover_name(name: &OsStr) -> bool {
    let b = name.as_bytes();
    b.starts_with(b"..env") && b.ends_with(b".tmp") && b.windows(10).any(|w| w == b".envcloak-")
}

/// The dotenv files under `r`. See the module documentation.
pub fn walk_dotenv<'r>(r: &'r ScanRoot, o: &WalkOptions) -> Walk<'r> {
    let mut visited = HashSet::new();
    visited.insert(r.identity());
    Walk {
        root: r,
        options: o.clone(),
        started: false,
        path: Vec::new(),
        pending: VecDeque::new(),
        visited,
        found: 0,
        directories: Vec::new(),
        skipped_dirs: Vec::new(),
        stopped: false,
    }
}

/// A directory on the walk's path down from the root: its handle, its path
/// from the root, its depth, and the subdirectories still to enter, by
/// name (popped from the end, so in name order).
#[derive(Debug)]
struct Frame {
    dir: File,
    rel: PathBuf,
    depth: usize,
    subdirs: Vec<OsString>,
}

/// The iterator [`walk_dotenv`] returns. It holds one descriptor for
/// each directory on its path, at most [`WalkOptions::max_depth`] and the
/// root's.
#[derive(Debug)]
pub struct Walk<'r> {
    root: &'r ScanRoot,
    options: WalkOptions,
    /// Whether the root was listed.
    started: bool,
    path: Vec<Frame>,
    pending: VecDeque<Result<FoundFile, ScanError>>,
    visited: HashSet<(u64, u64)>,
    found: usize,
    directories: Vec<PathBuf>,
    skipped_dirs: Vec<PathBuf>,
    stopped: bool,
}

impl Iterator for Walk<'_> {
    type Item = Result<FoundFile, ScanError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.stopped {
                return None;
            }
            if self.found >= self.options.max_files {
                self.stopped = true;
                return (!self.started
                    || !self.pending.is_empty()
                    || self.path.iter().any(|f| !f.subdirs.is_empty()))
                .then(|| {
                    Err(ScanError {
                        rel: PathBuf::new(),
                        kind: ScanErrorKind::FileBudget,
                    })
                });
            }
            if let Some(x) = self.pending.pop_front() {
                self.found += 1;
                return Some(x);
            }
            if !self.started {
                self.started = true;
                match self.root.dir().try_clone() {
                    Ok(d) => self.enter(d, PathBuf::new(), 0),
                    Err(e) => self.pending.push_back(Err(ScanError {
                        rel: PathBuf::new(),
                        kind: crate::root::io_kind(&e),
                    })),
                }
                continue;
            }
            let top = self.path.last_mut()?;
            let Some(name) = top.subdirs.pop() else {
                // Every subdirectory was entered: close this one.
                self.path.pop();
                continue;
            };
            let child = top.rel.join(&name);
            let depth = top.depth + 1;
            match self.root.open_subdir(&top.dir, &name) {
                Ok(sub) => {
                    let Ok(m) = sub.metadata() else { continue };
                    if self.visited.insert((m.dev(), m.ino())) {
                        self.enter(sub, child, depth);
                    }
                }
                // A symlink, or not a directory after all: not entered.
                Err(ScanErrorKind::Symlink | ScanErrorKind::NotRegular) => {}
                Err(k) => self.pending.push_back(Err(ScanError {
                    rel: child,
                    kind: k,
                })),
            }
        }
    }
}

impl Walk<'_> {
    /// Directories actually reached through the held root, in discovery order.
    pub fn directories(&self) -> &[PathBuf] {
        &self.directories
    }

    /// Directories deliberately omitted by the configured name rules.
    pub fn skipped_dirs(&self) -> &[PathBuf] {
        &self.skipped_dirs
    }

    /// Lists `dir` and puts it on the path, with the subdirectories to
    /// enter below it.
    fn enter(&mut self, dir: File, rel: PathBuf, depth: usize) {
        if self.directories.len() >= self.options.max_dirs {
            self.pending.push_back(Err(ScanError {
                rel,
                kind: ScanErrorKind::FileBudget,
            }));
            self.path.clear();
            return;
        }
        self.directories.push(rel.clone());
        let subdirs = self.list(&dir, &rel, depth);
        self.path.push(Frame {
            dir,
            rel,
            depth,
            subdirs,
        });
    }

    /// Reports the dotenv files of `dir` and returns the names of the
    /// subdirectories to enter, last first.
    fn list(&mut self, dir: &File, rel: &std::path::Path, depth: usize) -> Vec<OsString> {
        let report = |rel: PathBuf, kind| Err(ScanError { rel, kind });
        let mut entries = match list_dir(dir, MAX_DIR_ENTRIES) {
            Ok(e) => e,
            Err(e) => {
                let kind = if e.kind() == std::io::ErrorKind::OutOfMemory {
                    ScanErrorKind::TooManyEntries
                } else {
                    crate::root::io_kind(&e)
                };
                self.pending.push_back(report(rel.to_path_buf(), kind));
                return Vec::new();
            }
        };
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut subdirs = Vec::new();
        for e in entries {
            let child = rel.join(&e.name);
            if leftover_name(&e.name) {
                self.pending
                    .push_back(report(child, ScanErrorKind::Leftover));
                continue;
            }
            if let Some(kind) = dotenv_kind(&e.name) {
                let Ok(kind) = kind else {
                    self.pending
                        .push_back(report(child, ScanErrorKind::ProfileName));
                    continue;
                };
                match open_file(dir, &e.name, MAX_DOTENV) {
                    Ok((_, m)) => self.pending.push_back(Ok(FoundFile {
                        rel: child,
                        kind,
                        size: m.len(),
                        hard_linked: m.nlink() > 1,
                    })),
                    Err(k) => self.pending.push_back(report(child, k)),
                }
                continue;
            }
            let may_be_dir = matches!(e.kind, DirEntryKind::Dir | DirEntryKind::Unknown);
            if !self.options.recursive || !may_be_dir {
                continue;
            }
            if self.options.skip_dirs.contains(&e.name) {
                if self.skipped_dirs.len() >= self.options.max_dirs {
                    self.pending
                        .push_back(report(child, ScanErrorKind::FileBudget));
                    break;
                }
                self.skipped_dirs.push(child);
                continue;
            }
            if depth >= self.options.max_depth {
                if e.kind == DirEntryKind::Dir {
                    self.pending
                        .push_back(report(child, ScanErrorKind::TooDeep));
                }
                continue;
            }
            subdirs.push(e.name);
        }
        // Popped from the end: in name order.
        subdirs.reverse();
        subdirs
    }
}
