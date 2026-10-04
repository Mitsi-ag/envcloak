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
//!   the system, user and managed files and looked through, the folders
//!   above them included, within [`MAX_DIRS`] folders.

use std::io::Read as _;
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
    let project: Vec<Layer> = dirs_down(root.as_deref(), dir)
        .iter()
        .map(|d| read_layer(&Locations::codex_project_config(d)))
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

/// The projects the person trusts in Codex: `[projects."<path>"]` with
/// `trust_level = "trusted"`, in the system, user and managed files.
pub fn trusted_projects(l: &Locations) -> Vec<PathBuf> {
    let (below, managed) = non_project(l);
    let mut out: Vec<PathBuf> = Vec::new();
    for layer in below.iter().chain(std::iter::once(&managed)) {
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

/// Every `.codex/config.toml` at or below `root` (symlinks not followed:
/// Codex's working directory is a resolved path), other than Codex's own
/// directory's, each passed to `found`; within `budget` folders.
fn walk(
    root: &Path,
    codex_home: &Path,
    budget: &mut usize,
    found: &mut dyn FnMut(&Path) -> Result<(), Refusal>,
) -> Result<(), Refusal> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        if *budget == 0 {
            return Err(unknown(&format!(
                "the projects you trust in Codex hold more folders than EnvCloak looks through, \
                 among them {}, any of which may hold a .codex/config.toml",
                root.display()
            )));
        }
        *budget -= 1;
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(unknown(&format!(
                    "the folder {} in a project you trust could not be listed",
                    d.display()
                )));
            }
        };
        for e in rd {
            let Ok(e) = e else {
                return Err(unknown(&format!(
                    "the folder {} in a project you trust could not be listed",
                    d.display()
                )));
            };
            if !e.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let p = e.path();
            if e.file_name() == ".codex" && p != codex_home {
                found(&p.join("config.toml"))?;
            }
            stack.push(p);
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
/// a trusted project that cannot be listed, or more than [`MAX_DIRS`]
/// folders to look through.
pub fn other_layers_fit(l: &Locations) -> Result<(), Refusal> {
    other_layers_fit_within(l, MAX_DIRS)
}

/// [`other_layers_fit`], looking through at most `max_dirs` folders of
/// trusted projects.
///
/// # Errors
/// As [`other_layers_fit`].
pub fn other_layers_fit_within(l: &Locations, max_dirs: usize) -> Result<(), Refusal> {
    for p in l.codex_managed_preferences() {
        if std::fs::symlink_metadata(&p).is_ok() {
            return Err(unknown(&format!(
                "a device profile gives Codex managed settings ({})",
                p.display()
            )));
        }
    }
    let cloud = l.codex_cloud_config_cache();
    if std::fs::symlink_metadata(&cloud).is_ok() {
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
    for p in l.codex_profile_configs() {
        check(&p)?;
    }
    let codex_home =
        std::fs::canonicalize(l.codex_home()).unwrap_or_else(|_| l.codex_home().to_path_buf());
    let mut budget = max_dirs;
    let mut walked: Vec<PathBuf> = Vec::new();
    for project in trusted_projects(l) {
        // The folders above a project: its layers start at its root, which
        // a marker other than `.git` can put above it.
        for a in project.ancestors().skip(1) {
            if a.join(".codex") != codex_home {
                check(&Locations::codex_project_config(a))?;
            }
        }
        if walked.iter().any(|w| project.starts_with(w)) {
            continue;
        }
        let real = std::fs::canonicalize(&project).unwrap_or_else(|_| project.clone());
        walk(&real, &codex_home, &mut budget, &mut |p| check(p))?;
        walked.push(project);
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
