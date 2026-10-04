//! Codex's configuration as the pinned Codex merges it (rust-v0.159.2:
//! `codex-rs/config/src/loader/mod.rs`, `merge.rs`, `project_root_markers.rs`
//! and `codex-rs/core/src/agents_md.rs`), for the decisions that depend
//! on more than the `config.toml` EnvCloak edits (Codex review, round 6:
//! the installer read that one file as if it were the effective
//! configuration).
//!
//! Codex merges, lowest first: its system file (`/etc/codex/config.toml`),
//! settings an organization's workspace sends, the user's `config.toml`,
//! a profile file under `--profile`, each trusted project's
//! `.codex/config.toml` from the project root down to the working
//! directory, `-c` flags, then the legacy managed file
//! (`/etc/codex/managed_config.toml`) and a macOS device profile's
//! settings on top. Tables merge key by key; any other value, an array
//! included, is replaced by the higher layer's.
//!
//! - [`doc_view`]: the instruction settings a session in a directory
//!   gets: `project_doc_max_bytes` and `project_doc_fallback_filenames`
//!   as the merge leaves them (a higher layer's list replaces a lower
//!   one's, an empty list included), and the project root found by
//!   `project_root_markers` from the layers below the projects' (default
//!   `.git`; an empty list: the working directory alone).
//! - [`other_layers_fit`]: whether every other layer EnvCloak can find
//!   leaves the socket allowance limited to EnvCloak's socket: none holds
//!   a network setting the allowance would switch on, combine with or be
//!   changed by, and none that may hold one is out of EnvCloak's sight
//!   (a device profile, an organization's settings, a file or folder it
//!   cannot read). Trusted projects are found in the `projects` tables of
//!   the system, user, profile and managed files; each one, and each
//!   linked git worktree of it (Codex trusts a worktree through its main
//!   checkout), is looked through with the folders above it, by its name
//!   and by where that leads, within [`MAX_DIRS`] folders. With
//!   `allow_symlinked_codex_home` set in the user's `config.toml`, every
//!   folder Codex's own directory leads to, through folder links too, is
//!   looked through as well, trusted or not ([`SYMLINKED_HOME`]).
//!
//! A folder's project layer is read as Codex reads it
//! (`discover_project_layers`): its `.codex` followed through a symlink
//! when that is a folder, and skipped when it is not one or is Codex's
//! own directory, by its name or by where it leads.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::{ErrorKind, Read as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item, TableLike};
use zeroize::Zeroizing;

use crate::hosts::codex::DOC_BUDGET;
use crate::locations::Locations;
use crate::writer::Refusal;

/// The most of one layer read.
const MAX_LAYER: usize = crate::writer::MAX_FILE;

/// The most folders of trusted projects looked through for their
/// `.codex/config.toml` files: past it, what they set is not known.
pub const MAX_DIRS: usize = 50_000;

/// What reading one layer found.
#[derive(Debug)]
pub enum Layer {
    Absent,
    /// There, but not a file EnvCloak could read as TOML (or too large):
    /// what it sets is not known.
    Unreadable,
    Doc(DocumentMut),
}

/// Reads the layer at `path`, through a symlink as Codex does.
pub fn read_layer(path: &Path) -> Layer {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Layer::Absent,
        Err(_) => return Layer::Unreadable,
    };
    if !meta.is_file() || meta.len() > MAX_LAYER as u64 {
        return Layer::Unreadable;
    }
    let Ok(f) = std::fs::File::open(path) else {
        return Layer::Unreadable;
    };
    // A config can hold an MCP server's literal key: the bytes are wiped.
    let mut bytes = Zeroizing::new(Vec::new());
    if f.take(MAX_LAYER as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > MAX_LAYER
    {
        return Layer::Unreadable;
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Layer::Unreadable;
    };
    text.parse::<DocumentMut>()
        .map_or(Layer::Unreadable, Layer::Doc)
}

/// The strings of the array at `key`, when there is one (a value of
/// another type is no list).
fn strings(doc: &DocumentMut, key: &str) -> Option<Vec<String>> {
    doc.get(key).and_then(Item::as_array).map(|a| {
        a.iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()
    })
}

fn size(doc: &DocumentMut, key: &str) -> Option<usize> {
    doc.get(key)
        .and_then(Item::as_integer)
        .and_then(|n| usize::try_from(n).ok())
}

/// The layers below every project's, lowest first (system, user), and the
/// legacy managed one merged above all.
fn non_project(l: &Locations) -> (Vec<Layer>, Layer) {
    (
        vec![
            read_layer(&l.codex_system_config()),
            read_layer(&l.codex_config()),
        ],
        read_layer(&l.codex_managed_config()),
    )
}

/// The instruction settings a Codex session started in a directory gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocView {
    /// The bytes of instruction files Codex reads.
    pub limit: usize,
    /// The fallback names, in order, as Codex keeps them (no empty name,
    /// `.`, `..`, or one with a `/`).
    pub fallbacks: Vec<String>,
    /// The project root: the nearest directory at or above the session's
    /// that holds one of the markers; `None`: the session's directory is
    /// read alone.
    pub root: Option<PathBuf>,
}

/// The nearest directory at or above `dir` holding one of `markers` (an
/// empty list finds none).
pub fn project_root(dir: &Path, markers: &[String]) -> Option<PathBuf> {
    dir.ancestors()
        .find(|a| markers.iter().any(|m| std::fs::metadata(a.join(m)).is_ok()))
        .map(Path::to_path_buf)
}

/// Codex's own directory, by its name and by where it leads: a folder's
/// `.codex` that is either one holds the user's layer, which Codex does
/// not read again as a project's.
struct Home {
    spelled: PathBuf,
    real: PathBuf,
}

impl Home {
    fn of(l: &Locations) -> Home {
        let spelled = l.codex_home().to_path_buf();
        let real = std::fs::canonicalize(&spelled).unwrap_or_else(|_| spelled.clone());
        Home { spelled, real }
    }

    fn is(&self, dot_codex: &Path) -> bool {
        dot_codex == self.spelled
            || dot_codex == self.real
            || std::fs::canonicalize(dot_codex).is_ok_and(|r| r == self.real)
    }
}

/// What a folder's `.codex` is to Codex (`discover_project_layers`).
enum DotCodex {
    /// Not a folder, or not there: no layer (Codex skips a `.codex` it
    /// cannot look at too).
    None,
    /// Codex's own directory: the user's layer, not read again.
    Home,
    /// A layer: this `config.toml`, the folder followed through a symlink.
    Layer(PathBuf),
}

fn dot_codex(dir: &Path, home: &Home) -> DotCodex {
    let dot = dir.join(".codex");
    if !std::fs::metadata(&dot).is_ok_and(|m| m.is_dir()) {
        return DotCodex::None;
    }
    if home.is(&dot) {
        return DotCodex::Home;
    }
    DotCodex::Layer(dot.join("config.toml"))
}

/// The directories from `root` down to `dir`, root first; `dir` alone
/// without a root.
fn dirs_down(root: Option<&Path>, dir: &Path) -> Vec<PathBuf> {
    let Some(root) = root else {
        return vec![dir.to_path_buf()];
    };
    let mut out: Vec<PathBuf> = dir
        .ancestors()
        .take_while(|a| a.starts_with(root))
        .map(Path::to_path_buf)
        .collect();
    out.reverse();
    out
}

/// The instruction settings for a session in `dir` (a project's
/// directory), the project's layers read as Codex reads them once the
/// project is trusted (an untrusted project's instructions are not read
/// at all).
pub fn doc_view(l: &Locations, dir: &Path) -> DocView {
    let (below, managed) = non_project(l);
    let mut markers: Option<Vec<String>> = None;
    for layer in below.iter().chain(std::iter::once(&managed)) {
        if let Layer::Doc(d) = layer {
            if let Some(m) = strings(d, "project_root_markers") {
                markers = Some(m);
            }
        }
    }
    let markers = markers.unwrap_or_else(|| vec![".git".to_owned()]);
    let root = project_root(dir, &markers);
    let home = Home::of(l);
    let project: Vec<Layer> = dirs_down(root.as_deref(), dir)
        .iter()
        .map(|d| match dot_codex(d, &home) {
            DotCodex::Layer(p) => read_layer(&p),
            DotCodex::None | DotCodex::Home => Layer::Absent,
        })
        .collect();
    let mut limit = None;
    let mut fallbacks: Option<Vec<String>> = None;
    for layer in below
        .iter()
        .chain(project.iter())
        .chain(std::iter::once(&managed))
    {
        if let Layer::Doc(d) = layer {
            if let Some(n) = size(d, "project_doc_max_bytes") {
                limit = Some(n);
            }
            if let Some(f) = strings(d, "project_doc_fallback_filenames") {
                fallbacks = Some(f);
            }
        }
    }
    let mut names: Vec<String> = Vec::new();
    for n in fallbacks.unwrap_or_default() {
        if n.is_empty() || n == "." || n == ".." || n.contains(['/', '\0']) {
            continue;
        }
        if n != "AGENTS.override.md" && n != "AGENTS.md" && !names.contains(&n) {
            names.push(n);
        }
    }
    DocView {
        limit: limit.unwrap_or(DOC_BUDGET),
        fallbacks: names,
        root,
    }
}

/// The budget for the user's own `AGENTS.md`: the smallest of
/// [`DOC_BUDGET`] and every `project_doc_max_bytes` the layers below the
/// projects' and the managed one set (a larger one is not counted on).
pub fn user_doc_limit(l: &Locations) -> usize {
    let (below, managed) = non_project(l);
    below
        .iter()
        .chain(std::iter::once(&managed))
        .filter_map(|layer| match layer {
            Layer::Doc(d) => size(d, "project_doc_max_bytes"),
            _ => None,
        })
        .fold(DOC_BUDGET, usize::min)
}

/// The instruction file Codex reads in `dir`: the first of
/// `AGENTS.override.md`, `AGENTS.md` and the fallback names that is a
/// file there (symlinks followed, as Codex does).
pub fn file_read_in(dir: &Path, fallbacks: &[String]) -> Option<PathBuf> {
    ["AGENTS.override.md", "AGENTS.md"]
        .into_iter()
        .map(str::to_owned)
        .chain(fallbacks.iter().cloned())
        .map(|n| dir.join(n))
        .find(|p| std::fs::metadata(p).is_ok_and(|m| m.is_file()))
}

/// The files Codex reads before `dir`'s in a session there: one in each
/// directory from the project root down to `dir`'s parent, root first.
pub fn files_before(view: &DocView, dir: &Path) -> Vec<PathBuf> {
    let mut down = dirs_down(view.root.as_deref(), dir);
    down.pop();
    down.iter()
        .filter_map(|d| file_read_in(d, &view.fallbacks))
        .collect()
}

// ------------------------------------------------- the socket allowance

fn table<'a>(t: &'a dyn TableLike, key: &str) -> Option<&'a dyn TableLike> {
    t.get(key).and_then(Item::as_table_like)
}

/// Whether a table of settings (a layer's root or a profile) holds a
/// network setting the socket allowance would switch on, combine with or
/// be changed by: anything under `[features.network_proxy]` (or the
/// feature itself), the system proxy features, network access turned on,
/// permission profiles.
fn network_in(t: &dyn TableLike) -> bool {
    if t.contains_key("permissions") || t.contains_key("default_permissions") {
        return true;
    }
    if let Some(f) = t.get("features").and_then(Item::as_table_like) {
        if [
            "network_proxy",
            "respect_system_proxy",
            "system_proxy_fallback",
        ]
        .iter()
        .any(|k| f.contains_key(k))
        {
            return true;
        }
    }
    table(t, "sandbox_workspace_write")
        .and_then(|s| s.get("network_access"))
        .is_some_and(|v| v.as_bool() != Some(false))
}

/// Whether a layer holds a network setting ([`network_in`]), at its root,
/// in a profile, or, for the requirements, as network requirements.
pub fn holds_network(doc: &DocumentMut) -> bool {
    let root = doc.as_table();
    if network_in(root) || root.contains_key("network") {
        return true;
    }
    table(root, "profiles").is_some_and(|ps| {
        ps.iter()
            .any(|(_, p)| p.as_table_like().is_none_or(network_in))
    })
}

fn present(path: &Path) -> Refusal {
    Refusal::new(
        "network_settings_present",
        format!(
            "Codex's settings in {} hold network settings of their own (a proxy domain rule, \
             another allowed socket, another proxy option, network access, a permission profile), \
             which EnvCloak's socket allowance would switch on or combine with, so it would not be \
             limited to EnvCloak's socket: the allowance was not written. Remove them, or add the \
             unix_sockets rule for EnvCloak's socket to your own settings, and run this again",
            path.display()
        ),
    )
}

fn unknown(why: &str) -> Refusal {
    Refusal::new(
        "network_settings_unknown",
        format!(
            "EnvCloak cannot read every Codex setting its socket allowance would combine with \
             ({why}), so it cannot keep the allowance limited to EnvCloak's socket: the allowance \
             was not written. Add the unix_sockets rule for EnvCloak's socket to your own settings \
             yourself if you want it"
        ),
    )
}

/// One layer, read for [`other_layers_fit`].
fn check(path: &Path) -> Result<(), Refusal> {
    match read_layer(path) {
        Layer::Absent => Ok(()),
        Layer::Unreadable => Err(unknown(&format!(
            "{} could not be read as TOML",
            path.display()
        ))),
        Layer::Doc(d) if holds_network(&d) => Err(present(path)),
        Layer::Doc(_) => Ok(()),
    }
}

/// A folder's project layer, read for [`other_layers_fit`].
fn check_dir(dir: &Path, home: &Home) -> Result<(), Refusal> {
    match dot_codex(dir, home) {
        DotCodex::Layer(p) => check(&p),
        DotCodex::None | DotCodex::Home => Ok(()),
    }
}

fn not_there(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

/// Whether `path` is there, looked at without following a symlink.
fn exists(path: &Path) -> Result<bool, Refusal> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if not_there(&e) => Ok(false),
        Err(_) => Err(unknown(&format!(
            "{} could not be looked at",
            path.display()
        ))),
    }
}

/// The layers Codex learns from which projects are trusted and where a
/// project's root is (the settings merged below the projects'): the
/// system file, the user's, each profile file (any session may name one)
/// and the managed file.
fn settings_layers(l: &Locations, profiles: &[PathBuf]) -> Vec<(PathBuf, Layer)> {
    let mut paths = vec![l.codex_system_config(), l.codex_config()];
    paths.extend(profiles.iter().cloned());
    paths.push(l.codex_managed_config());
    paths
        .into_iter()
        .map(|p| {
            let layer = read_layer(&p);
            (p, layer)
        })
        .collect()
}

/// The projects the person trusts in Codex: `[projects."<path>"]` with
/// `trust_level = "trusted"`, in `layers`.
fn trusted_projects(layers: &[(PathBuf, Layer)]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for (_, layer) in layers {
        let Layer::Doc(d) = layer else {
            continue;
        };
        let Some(projects) = table(d.as_table(), "projects") else {
            continue;
        };
        for (k, v) in projects.iter() {
            let trusted = v
                .as_table_like()
                .and_then(|t| t.get("trust_level"))
                .and_then(Item::as_str)
                == Some("trusted");
            let p = PathBuf::from(k);
            if trusted && p.is_absolute() && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The most of a git metadata file read (Codex reads no more).
const MAX_GIT_FILE: u64 = 64 * 1024;

/// A git metadata file's bytes; `None` when it is not there, not a file
/// or larger than Codex reads.
fn git_file(path: &Path) -> Result<Option<Vec<u8>>, Refusal> {
    let cannot = || unknown(&format!("{} could not be read", path.display()));
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() && m.len() <= MAX_GIT_FILE => {}
        Ok(_) => return Ok(None),
        Err(e) if not_there(&e) => return Ok(None),
        Err(_) => return Err(cannot()),
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_GIT_FILE + 1).read_to_end(&mut bytes))
        .map_err(|_| cannot())?;
    Ok(Some(bytes))
}

/// The linked git worktrees of the repository checked out at `project`:
/// Codex trusts a folder in one through its main checkout
/// (`resolve_root_git_project_for_trust`), and reads the worktree's own
/// `.codex/config.toml` files (`merge_root_checkout_project_hooks` takes
/// only the hooks from the main checkout's). Each checkout named by a
/// `worktrees/*/gitdir` file of the repository's git directory (`.git`, or
/// the one a `.git` file names) is one, whether Codex would accept its
/// links or not.
fn linked_worktrees(project: &Path) -> Result<Vec<PathBuf>, Refusal> {
    let dot_git = project.join(".git");
    let git_dir = match std::fs::metadata(&dot_git) {
        Ok(m) if m.is_dir() => dot_git,
        Ok(_) => {
            let named = git_file(&dot_git)?.and_then(|text| {
                let t = text.trim_ascii().strip_prefix(b"gitdir:")?.trim_ascii();
                (!t.is_empty()).then(|| project.join(OsStr::from_bytes(t)))
            });
            match named {
                Some(d) => d,
                None => return Ok(Vec::new()),
            }
        }
        Err(e) if not_there(&e) => return Ok(Vec::new()),
        Err(_) => {
            return Err(unknown(&format!(
                "{} could not be looked at",
                dot_git.display()
            )));
        }
    };
    let listed = git_dir.join("worktrees");
    let cannot = || {
        unknown(&format!(
            "the worktrees of the project you trust at {} could not be listed ({})",
            project.display(),
            listed.display()
        ))
    };
    let rd = match std::fs::read_dir(&listed) {
        Ok(rd) => rd,
        Err(e) if not_there(&e) => return Ok(Vec::new()),
        Err(_) => return Err(cannot()),
    };
    let mut out = Vec::new();
    for e in rd {
        let entry = e.map_err(|_| cannot())?.path();
        let Some(text) = git_file(&entry.join("gitdir"))? else {
            continue;
        };
        let t = text.trim_ascii();
        if t.is_empty() {
            continue;
        }
        // A relative path is read from the worktree's entry, resolved.
        let base = std::fs::canonicalize(&entry).unwrap_or(entry);
        let dot = base.join(OsStr::from_bytes(t));
        if let Some(checkout) = dot.parent() {
            out.push(checkout.to_path_buf());
        }
    }
    out.sort();
    Ok(out)
}

/// The key in the user's `config.toml` that lets Codex's `workspace-write`
/// sandbox take a writable root at or beneath Codex's directory named
/// through folder links (pinned 0.159.2: `allow_symlinked_codex_home`,
/// read from the user's own file at its top level only,
/// `codex-rs/config/src/codex_home_symlink.rs`; the sandbox's refusal of a
/// symlinked writable root names it, `codex-rs/sandboxing/src/seatbelt.rs`).
/// With it, a session named through a link beneath Codex's directory
/// runs its commands, and reads the layers of the folders the link leads
/// to (measured in `m2_story`, the verifier's round-7 finding): those
/// folders are looked through too.
pub const SYMLINKED_HOME: &str = "allow_symlinked_codex_home";

/// Whether the user's `config.toml` sets [`SYMLINKED_HOME`]: any value but
/// `false` is counted as set (Codex reads only `true`, and refuses a file
/// whose value is not a boolean).
///
/// # Errors
/// `network_settings_unknown` when the file is there and not readable
/// TOML.
fn symlinked_home_allowed(l: &Locations) -> Result<bool, Refusal> {
    let path = l.codex_config();
    match read_layer(&path) {
        Layer::Absent => Ok(false),
        Layer::Unreadable => Err(unknown(&format!(
            "{} could not be read as TOML",
            path.display()
        ))),
        Layer::Doc(d) => Ok(d
            .get(SYMLINKED_HOME)
            .is_some_and(|v| v.as_bool() != Some(false))),
    }
}

/// Every folder at or below `root`, each one's project layer passed to
/// [`check_dir`]; within `budget` folders, each counted once for each way
/// of walking (`seen`: device, inode, and whether links are followed; a
/// folder walked with links followed is not walked again without).
///
/// Without `follow`, a folder link is not followed: a session Codex
/// starts in a folder it finds itself is in a resolved path, and one named
/// through a link (`codex -C`) runs no command in Codex's
/// `workspace-write` sandbox, the one the allowance is for (pinned
/// 0.159.2, measured in `m2_story`: "symlinked writable roots are not
/// supported"), unless the root is at or beneath Codex's directory and
/// the user's `config.toml` sets [`SYMLINKED_HOME`]: then Codex's
/// directory is walked with `follow`, every folder link taken (measured
/// in `m2_story`: a session named through such a link runs its commands
/// and reads the layer the link leads to). A folder's `.codex` that is a
/// link is read either way ([`dot_codex`]).
fn walk(
    root: &Path,
    home: &Home,
    follow: bool,
    budget: &mut usize,
    seen: &mut HashSet<(u64, u64, bool)>,
) -> Result<(), Refusal> {
    // Where the walk is, for its messages.
    let place = if follow {
        "in Codex's directory, whose folder links allow_symlinked_codex_home lets Codex follow"
    } else {
        "in a project you trust"
    };
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let meta = match std::fs::metadata(&d) {
            Ok(m) if m.is_dir() => m,
            Ok(_) => continue,
            Err(e) if not_there(&e) => continue,
            Err(_) => {
                return Err(unknown(&format!(
                    "the folder {} {place} could not be looked at",
                    d.display()
                )));
            }
        };
        let (dev, ino) = (meta.dev(), meta.ino());
        let first = if follow {
            seen.insert((dev, ino, true))
        } else {
            !seen.contains(&(dev, ino, true)) && seen.insert((dev, ino, false))
        };
        if !first {
            continue;
        }
        if *budget == 0 {
            return Err(unknown(&format!(
                "the projects you trust in Codex (and Codex's directory, with \
                 allow_symlinked_codex_home) hold more folders than EnvCloak looks through, among \
                 them {}, any of which may hold a .codex/config.toml",
                root.display()
            )));
        }
        *budget -= 1;
        check_dir(&d, home)?;
        let cannot = || {
            unknown(&format!(
                "the folder {} {place} could not be listed",
                d.display()
            ))
        };
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(e) if not_there(&e) => continue,
            Err(_) => return Err(cannot()),
        };
        for e in rd {
            let e = e.map_err(|_| cannot())?;
            let kind = e.file_type().map_err(|_| cannot())?;
            if kind.is_dir() || (follow && kind.is_symlink()) {
                stack.push(e.path());
            }
        }
    }
    Ok(())
}

/// Whether every Codex layer other than the user's `config.toml` (which
/// the allowance is written into and `hosts::codex` reads) leaves the
/// socket allowance limited to EnvCloak's socket (Codex review, round 6:
/// a domain or socket rule in the system file, a profile or a trusted
/// project was switched on by the allowance's `network_access` and
/// proxy).
///
/// # Errors
/// `network_settings_present` when a layer holds a network setting;
/// `network_settings_unknown` when one may and cannot be read: a macOS
/// device profile for Codex, a cache of an organization's settings (they
/// come with the account), a file that is not readable TOML, a folder of
/// a trusted project or of its worktrees that cannot be listed, or more
/// than [`MAX_DIRS`] folders to look through.
pub fn other_layers_fit(l: &Locations) -> Result<(), Refusal> {
    other_layers_fit_within(l, MAX_DIRS)
}

/// [`other_layers_fit`], looking through at most `max_dirs` folders of
/// trusted projects.
///
/// # Errors
/// As [`other_layers_fit`].
pub fn other_layers_fit_within(l: &Locations, max_dirs: usize) -> Result<(), Refusal> {
    let prefs = l.codex_managed_preferences().map_err(|e| {
        unknown(&format!(
            "the managed preferences, where a device profile would give Codex settings, could \
             not be listed ({e})"
        ))
    })?;
    for p in prefs {
        if exists(&p)? {
            return Err(unknown(&format!(
                "a device profile gives Codex managed settings ({})",
                p.display()
            )));
        }
    }
    let cloud = l.codex_cloud_config_cache();
    if exists(&cloud)? {
        return Err(unknown(&format!(
            "your account's workspace sends Codex settings of its own ({} is there)",
            cloud.display()
        )));
    }
    for p in [
        l.codex_system_config(),
        l.codex_managed_config(),
        l.codex_requirements(),
    ] {
        check(&p)?;
    }
    let profiles = l.codex_profile_configs().map_err(|e| {
        unknown(&format!(
            "Codex's directory, where its profile files are, could not be listed ({e})"
        ))
    })?;
    for p in &profiles {
        check(p)?;
    }
    let layers = settings_layers(l, &profiles);
    let home = Home::of(l);
    let mut budget = max_dirs;
    let mut seen: HashSet<(u64, u64, bool)> = HashSet::new();
    let mut above: HashSet<PathBuf> = HashSet::new();
    for project in trusted_projects(&layers) {
        let mut roots = vec![project.clone()];
        roots.extend(linked_worktrees(&project)?);
        for root in roots {
            // The folders above a checkout, by its name and where it leads:
            // a root found by a marker other than `.git` can be one of them
            // (a session's folder is a resolved path, so its folders above
            // are those where the checkout's name leads).
            let real = std::fs::canonicalize(&root).ok();
            let ups = root
                .ancestors()
                .skip(1)
                .chain(real.iter().flat_map(|r| r.ancestors().skip(1)));
            for a in ups {
                if above.insert(a.to_path_buf()) {
                    check_dir(a, &home)?;
                }
            }
            walk(&root, &home, false, &mut budget, &mut seen)?;
        }
    }
    // With `allow_symlinked_codex_home`, a session's folder at or beneath
    // Codex's directory may be named through folder links, and Codex reads
    // the layers of every folder from its project root down to it: the
    // folders above Codex's directory, and every folder it leads to, links
    // followed (trusted or not: a folder reached through a link is trusted
    // by its own name, where it leads, or its project root's, which the
    // walk does not work out).
    if symlinked_home_allowed(l)? {
        for start in [&home.spelled, &home.real] {
            for a in start.ancestors().skip(1) {
                if above.insert(a.to_path_buf()) {
                    check_dir(a, &home)?;
                }
            }
            walk(start, &home, true, &mut budget, &mut seen)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(t: &str) -> DocumentMut {
        t.parse().unwrap()
    }

    #[test]
    fn network_settings_are_found_wherever_a_layer_holds_them() {
        for t in [
            "[features.network_proxy]\ndomains = { \"example.com\" = \"allow\" }",
            "[features]\nnetwork_proxy = false",
            "features = { network_proxy = { enabled = false } }",
            "[features.network_proxy.unix_sockets]\n\"/tmp/x.sock\" = \"allow\"",
            "[features]\nrespect_system_proxy = true",
            "[sandbox_workspace_write]\nnetwork_access = true",
            "default_permissions = \"p\"",
            "[permissions.p.network]\nenabled = true",
            "[profiles.work.features.network_proxy]\nenabled = true",
            "[profiles.work.sandbox_workspace_write]\nnetwork_access = true",
            "profiles = { work = 1 }",
            "[network]\nallowed_domains = [\"example.com\"]",
        ] {
            assert!(holds_network(&doc(t)), "{t}");
        }
        for t in [
            "",
            "model = \"m\"",
            "[sandbox_workspace_write]\nnetwork_access = false",
            "[features]\nhooks = true",
            "[projects.\"/w\"]\ntrust_level = \"trusted\"",
            "[profiles.work]\nmodel = \"m\"",
        ] {
            assert!(!holds_network(&doc(t)), "{t}");
        }
    }
}
