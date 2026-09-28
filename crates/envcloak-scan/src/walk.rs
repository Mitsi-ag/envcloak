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
//!   [`WalkOptions::max_depth`] and [`WalkOptions::max_files`].
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
//! [`FileKind::Template`].

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
    /// Directory names never entered.
    pub skip_dirs: Vec<OsString>,
}

impl Default for WalkOptions {
    fn default() -> Self {
        WalkOptions {
            recursive: false,
            max_depth: 12,
            max_files: 10_000,
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
    if TEMPLATE_SUFFIXES.contains(&suffix.as_str()) {
        return Some(Ok(FileKind::Template));
    }
    Some(
        ProfileName::new(&suffix.replace('.', "-"))
            .map(|p| FileKind::Dotenv { profile: Some(p) })
            .map_err(|_| ()),
    )
}

/// The dotenv files under `r`. See the module documentation.
pub fn walk_dotenv<'r>(r: &'r ScanRoot, o: &WalkOptions) -> Walk<'r> {
    let mut stack = Vec::new();
    let mut pending = VecDeque::new();
    match r.dir().try_clone() {
        Ok(d) => stack.push((d, PathBuf::new(), 0)),
        Err(e) => pending.push_back(Err(ScanError {
            rel: PathBuf::new(),
            kind: crate::root::io_kind(&e),
        })),
    }
    let mut visited = HashSet::new();
    visited.insert(r.identity());
    Walk {
        root: r,
        options: o.clone(),
        stack,
        pending,
        visited,
        found: 0,
    }
}

/// The iterator [`walk_dotenv`] returns.
#[derive(Debug)]
pub struct Walk<'r> {
    root: &'r ScanRoot,
    options: WalkOptions,
    /// Directories still to list: the handle, the path from the root and
    /// the depth.
    stack: Vec<(File, PathBuf, usize)>,
    pending: VecDeque<Result<FoundFile, ScanError>>,
    visited: HashSet<(u64, u64)>,
    found: usize,
}

impl Iterator for Walk<'_> {
    type Item = Result<FoundFile, ScanError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(x) = self.pending.pop_front() {
                if x.is_ok() {
                    self.found += 1;
                }
                return Some(x);
            }
            if self.found >= self.options.max_files {
                return None;
            }
            let (dir, rel, depth) = self.stack.pop()?;
            self.list(&dir, &rel, depth);
        }
    }
}

impl Walk<'_> {
    fn list(&mut self, dir: &File, rel: &std::path::Path, depth: usize) {
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
                return;
            }
        };
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut subdirs = Vec::new();
        for e in entries {
            let child = rel.join(&e.name);
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
            if !self.options.recursive || !may_be_dir || self.options.skip_dirs.contains(&e.name) {
                continue;
            }
            if depth >= self.options.max_depth {
                if e.kind == DirEntryKind::Dir {
                    self.pending
                        .push_back(report(child, ScanErrorKind::TooDeep));
                }
                continue;
            }
            match self.root.open_subdir(dir, &e.name) {
                Ok(sub) => {
                    let Ok(m) = sub.metadata() else { continue };
                    if self.visited.insert((m.dev(), m.ino())) {
                        subdirs.push((sub, child, depth + 1));
                    }
                }
                // A symlink, or not a directory after all: not entered.
                Err(ScanErrorKind::Symlink | ScanErrorKind::NotRegular) => {}
                Err(k) => self.pending.push_back(report(child, k)),
            }
        }
        // Popped in name order.
        subdirs.reverse();
        self.stack.extend(subdirs);
    }
}
