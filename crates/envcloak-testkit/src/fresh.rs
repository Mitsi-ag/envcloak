//! Whether a binary in a cargo target directory is older than the sources
//! it is built from (group 3 verification, G3-V2).
//!
//! A test that runs another package's binary runs whatever cargo last
//! built there: the CLI's tests run `envcloakd`, the end-to-end tests both
//! binaries, and `cargo test -p envcloak` rebuilds neither `envcloakd` nor
//! anything for it. After a change to envcloak-core such a run tests the
//! old daemon, and a mutation check made that way passes when it should
//! fail. [`assert_fresh`] refuses the binary instead.
//!
//! The sources are the files rustc read to build the binary and every
//! workspace library it depends on, as the dep-info files cargo keeps in
//! `deps/` list them: `<crate>-<hash>.d` beside the binary's own copy
//! there, and beside each `lib<crate>-<hash>.rlib` of those libraries.
//! Every library build the directory holds counts, so a file only a test
//! feature compiles counts too (`cargo test -p <package> --no-run` builds
//! the binary with its tests' features, which read it). A listed file
//! changed after the binary was linked is one cargo would rebuild it for.
//! A listed file that no longer exists is left out: the file that named
//! it changed as well.
//!
//! Only those files count (review R-2). A change to a manifest (features,
//! dependency versions), to `Cargo.lock`, to build flags or to a variable
//! a crate reads with `env!` is not seen: cargo rebuilds for some of those
//! and not for others (a comment, a dev-dependency, another package's
//! lock entry), and counting them would refuse a binary that no rebuild
//! makes newer. CONTRIBUTING says to build the binaries after such a
//! change.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use toml_edit::{Document, Item, TableLike};

/// A workspace member, as its manifest gives it.
#[derive(Debug)]
struct Member {
    /// The library's crate name, when the package has one.
    lib: Option<String>,
    /// The packages it depends on (normal dependencies, for any target).
    deps: Vec<String>,
}

/// The first of the sources `bin` was built from, in path order, that
/// changed after it was linked: `None` when none did. `bin` is a binary
/// of the workspace package `package` in a cargo target directory
/// (`<profile>/<name>`, beside that profile's `deps/`), and `root` the
/// workspace root, which relative paths in the dep-info files are under.
///
/// # Errors
/// The workspace or the target directory cannot be read, `package` is
/// not a member, or the directory holds no dep-info for the binary or
/// for one of its libraries (it was not built there by cargo): nothing
/// then says the binary is fresh.
pub fn stale_source(bin: &Path, package: &str, root: &Path) -> Result<Option<PathBuf>, String> {
    let meta = std::fs::metadata(bin).map_err(|e| format!("{}: {e}", bin.display()))?;
    let linked = modified(&meta, bin)?;
    let deps = bin
        .parent()
        .map(|p| p.join("deps"))
        .ok_or_else(|| format!("{} is not in a target directory", bin.display()))?;
    let name = bin
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| format!("{} has no usable file name", bin.display()))?;
    let members = members(root)?;
    let libs = closure(&members, package)?;
    let entries = deps_entries(&deps)?;

    let mut infos = bin_dep_infos(&deps, &entries, &name.replace('-', "_"), &meta, linked)?;
    for lib in &libs {
        let found = lib_dep_infos(&deps, &entries, lib);
        if found.is_empty() {
            return Err(format!(
                "no build of the library {lib} in {}",
                deps.display()
            ));
        }
        infos.extend(found);
    }

    let mut sources = BTreeSet::new();
    for info in &infos {
        let bytes = std::fs::read(info).map_err(|e| format!("{}: {e}", info.display()))?;
        for dep in dep_info_sources(&bytes) {
            sources.insert(root.join(dep));
        }
    }
    for source in sources {
        match std::fs::metadata(&source) {
            Ok(m) if modified(&m, &source)? > linked => return Ok(Some(source)),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", source.display())),
        }
    }
    Ok(None)
}

/// Panics unless `bin`, a binary of the workspace package `package` in
/// the target directory the tests were built in, is no older than any
/// source it is built from (see [`stale_source`]).
///
/// # Panics
/// When it is older, naming the source and how to rebuild it, or when
/// that cannot be told.
pub fn assert_fresh(bin: &Path, package: &str) {
    assert_fresh_or(bin, package, &format!("cargo test -p {package} --no-run"));
}

/// [`assert_fresh`], naming `rebuild` as the command that builds `bin`.
pub(crate) fn assert_fresh_or(bin: &Path, package: &str, rebuild: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap_or_else(|| panic!("the testkit is not in a workspace"));
    match stale_source(bin, package, root) {
        Ok(None) => {}
        Ok(Some(source)) => panic!(
            "{} is older than {}, which it is built from: cargo did not rebuild it for this \
             run, and a test of it would test the old code (cargo test -p <another package> \
             leaves it as it is). Build it first with {rebuild}, or run the tests with \
             --workspace.",
            bin.display(),
            source.display()
        ),
        Err(e) => panic!(
            "cannot tell whether {} is as new as its sources: {e}",
            bin.display()
        ),
    }
}

fn modified(meta: &std::fs::Metadata, path: &Path) -> Result<SystemTime, String> {
    meta.modified()
        .map_err(|e| format!("{}: no modification time: {e}", path.display()))
}

/// The names in `deps`.
fn deps_entries(deps: &Path) -> Result<Vec<String>, String> {
    let dir = std::fs::read_dir(deps).map_err(|e| format!("{}: {e}", deps.display()))?;
    let mut out = Vec::new();
    for entry in dir {
        let entry = entry.map_err(|e| format!("{}: {e}", deps.display()))?;
        // Cargo's names are ASCII; any other is not one of its outputs.
        if let Some(name) = entry.file_name().to_str() {
            out.push(name.to_owned());
        }
    }
    Ok(out)
}

/// Whether `name` is `<prefix>-<16 hex digits><suffix>`.
fn unit_hash<'a>(name: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let hash = name
        .strip_prefix(prefix)?
        .strip_prefix('-')?
        .strip_suffix(suffix)?;
    (hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hash)
}

/// The dep-info of the build `bin` is a copy of: its `deps/<crate>-<hash>`
/// with the same length and modification time (cargo links or copies it
/// out keeping both). When none matches, that of every build of the
/// crate, which may list more files than the binary read, never fewer.
fn bin_dep_infos(
    deps: &Path,
    entries: &[String],
    krate: &str,
    meta: &std::fs::Metadata,
    linked: SystemTime,
) -> Result<Vec<PathBuf>, String> {
    let mut all = Vec::new();
    let mut same = Vec::new();
    for name in entries {
        if unit_hash(name, krate, "").is_none() {
            continue;
        }
        let info = deps.join(format!("{name}.d"));
        if !info.is_file() {
            continue;
        }
        let unit = std::fs::metadata(deps.join(name)).map_err(|e| format!("{name}: {e}"))?;
        if unit.len() == meta.len() && unit.modified().ok() == Some(linked) {
            same.push(info.clone());
        }
        all.push(info);
    }
    if all.is_empty() {
        return Err(format!("no dep-info for {krate} in {}", deps.display()));
    }
    Ok(if same.is_empty() { all } else { same })
}

/// The dep-info of every build of the library `lib` in `deps`: each
/// `<lib>-<hash>.d` beside a `lib<lib>-<hash>.rlib`. Test builds of the
/// library (executables, no rlib) are not among them.
fn lib_dep_infos(deps: &Path, entries: &[String], lib: &str) -> Vec<PathBuf> {
    let rlib = format!("lib{lib}");
    entries
        .iter()
        .filter_map(|name| unit_hash(name, &rlib, ".rlib"))
        .map(|hash| deps.join(format!("{lib}-{hash}.d")))
        .filter(|info| info.is_file())
        .collect()
}

/// The prerequisites a dep-info file lists, in Makefile syntax: the words
/// after each `target:`, a space in a path escaped as `\ `. Comment lines
/// (rustc's `# env-dep:`) are skipped. Paths are bytes, as the file has
/// them.
fn dep_info_sources(bytes: &[u8]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for line in bytes.split(|&b| b == b'\n') {
        if line.first() == Some(&b'#') {
            continue;
        }
        let mut words = Vec::new();
        let mut word = Vec::new();
        let mut i = 0;
        while i < line.len() {
            match line[i] {
                b'\\' if line.get(i + 1) == Some(&b' ') => {
                    word.push(b' ');
                    i += 1;
                }
                b' ' | b'\t' | b'\r' => {
                    if !word.is_empty() {
                        words.push(std::mem::take(&mut word));
                    }
                }
                b => word.push(b),
            }
            i += 1;
        }
        if !word.is_empty() {
            words.push(word);
        }
        let Some(target) = words.iter().position(|w| w.last() == Some(&b':')) else {
            continue;
        };
        out.extend(
            words[target + 1..]
                .iter()
                .map(|w| PathBuf::from(OsStr::from_bytes(w))),
        );
    }
    out
}

/// The workspace's members by package name, from `root/Cargo.toml`'s
/// `workspace.members` (paths, or a directory followed by `/*`).
fn members(root: &Path) -> Result<HashMap<String, Member>, String> {
    let manifest = root.join("Cargo.toml");
    let text = read_text(&manifest)?;
    let doc = parse(&text, &manifest)?;
    let list = doc
        .as_table()
        .get("workspace")
        .and_then(Item::as_table_like)
        .and_then(|w| w.get("members"))
        .and_then(Item::as_array)
        .ok_or_else(|| format!("{}: no workspace.members", manifest.display()))?;
    let mut dirs = Vec::new();
    for entry in list {
        let entry = entry
            .as_str()
            .ok_or_else(|| format!("{}: a member that is not a path", manifest.display()))?;
        if let Some(parent) = entry.strip_suffix("/*") {
            let parent = root.join(parent);
            let read =
                std::fs::read_dir(&parent).map_err(|e| format!("{}: {e}", parent.display()))?;
            for d in read {
                let d = d.map_err(|e| format!("{}: {e}", parent.display()))?.path();
                if d.join("Cargo.toml").is_file() {
                    dirs.push(d);
                }
            }
        } else if entry.contains(['*', '?', '[']) {
            return Err(format!(
                "{}: unsupported member pattern {entry}",
                manifest.display()
            ));
        } else {
            dirs.push(root.join(entry));
        }
    }
    let mut out = HashMap::new();
    for dir in dirs {
        let (name, member) = member(&dir)?;
        out.insert(name, member);
    }
    Ok(out)
}

fn member(dir: &Path) -> Result<(String, Member), String> {
    let manifest = dir.join("Cargo.toml");
    let text = read_text(&manifest)?;
    let doc = parse(&text, &manifest)?;
    let top = doc.as_table();
    let name = top
        .get("package")
        .and_then(Item::as_table_like)
        .and_then(|p| p.get("name"))
        .and_then(Item::as_str)
        .ok_or_else(|| format!("{}: no package.name", manifest.display()))?
        .to_owned();
    let lib_table = top.get("lib").and_then(Item::as_table_like);
    let lib = match lib_table.and_then(|l| l.get("name")).and_then(Item::as_str) {
        Some(n) => Some(n.to_owned()),
        None if lib_table.is_some() || dir.join("src/lib.rs").is_file() => {
            Some(name.replace('-', "_"))
        }
        None => None,
    };
    let mut deps = Vec::new();
    let mut tables: Vec<&dyn TableLike> = Vec::new();
    if let Some(t) = top.get("dependencies").and_then(Item::as_table_like) {
        tables.push(t);
    }
    if let Some(targets) = top.get("target").and_then(Item::as_table_like) {
        for (_, target) in targets.iter() {
            if let Some(t) = target
                .as_table_like()
                .and_then(|t| t.get("dependencies"))
                .and_then(Item::as_table_like)
            {
                tables.push(t);
            }
        }
    }
    for table in tables {
        for (key, item) in table.iter() {
            // A renamed dependency names its package.
            let package = item
                .as_table_like()
                .and_then(|t| t.get("package"))
                .and_then(Item::as_str);
            deps.push(match package {
                Some(p) => p.to_owned(),
                None => key.to_owned(),
            });
        }
    }
    Ok((name, Member { lib, deps }))
}

/// The libraries of `package` and of every workspace member it depends
/// on, directly or not.
fn closure(members: &HashMap<String, Member>, package: &str) -> Result<Vec<String>, String> {
    if !members.contains_key(package) {
        return Err(format!("{package} is not a workspace member"));
    }
    let mut seen = BTreeSet::from([package.to_owned()]);
    let mut queue = VecDeque::from([package.to_owned()]);
    let mut libs = Vec::new();
    while let Some(p) = queue.pop_front() {
        let Some(m) = members.get(&p) else { continue };
        if let Some(lib) = &m.lib {
            libs.push(lib.clone());
        }
        for d in &m.deps {
            if members.contains_key(d) && seen.insert(d.clone()) {
                queue.push_back(d.clone());
            }
        }
    }
    Ok(libs)
}

fn read_text(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    String::from_utf8(bytes).map_err(|_| format!("{}: not UTF-8", path.display()))
}

fn parse<'a>(text: &'a str, path: &Path) -> Result<Document<&'a str>, String> {
    Document::parse(text).map_err(|e| format!("{}: {}", path.display(), e.message()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dep_info_lists_the_prerequisites_of_every_target() {
        let text = b"/t/deps/x-0123456789abcdef.d: src/main.rs src/a\\ b.rs\n\n\
/t/deps/x-0123456789abcdef: src/main.rs src/a\\ b.rs src/\xff.rs\n\nsrc/main.rs:\n\
# env-dep:CARGO_PKG_VERSION=0.1.0\n";
        let got = dep_info_sources(text);
        let want: Vec<PathBuf> = [
            &b"src/main.rs"[..],
            b"src/a b.rs",
            b"src/main.rs",
            b"src/a b.rs",
            b"src/\xff.rs",
        ]
        .iter()
        .map(|b| PathBuf::from(OsStr::from_bytes(b)))
        .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn unit_names_carry_sixteen_hex_digits() {
        assert_eq!(
            unit_hash(
                "libenvcloak_core-0123456789abcdef.rlib",
                "libenvcloak_core",
                ".rlib"
            ),
            Some("0123456789abcdef")
        );
        for name in [
            "libenvcloak_core-0123456789abcde.rlib",
            "libenvcloak_core-0123456789abcdeg.rlib",
            "libenvcloak_core_x-0123456789abcdef.rlib",
            "libenvcloak_core-0123456789abcdef.rmeta",
        ] {
            assert_eq!(unit_hash(name, "libenvcloak_core", ".rlib"), None, "{name}");
        }
    }
}
