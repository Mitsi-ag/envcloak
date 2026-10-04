//! An independent check of how the socket allowance's layer walk finds a
//! trusted repository's linked worktrees, against the identity checks the
//! pinned Codex makes before it trusts a worktree through its main
//! checkout (rust-v0.159.2 `codex-rs/config/src/loader/mod.rs`, the trust
//! decision for a directory, and `trust.rs`, which reads the worktree's
//! `.git` pointer and its registration), adopted in its 19 cases from the
//! review's gate. Git's metadata is written by hand, so no git runs.
//!
//! Each case is one repository, its worktree and Codex's settings; the
//! layer that matters holds TOML that does not parse, so a check that
//! reads it answers `network_settings_unknown` and one that does not fits.
//! Three readings per case:
//!
//! - the fixture graph: whether the worktree's registration is one Codex
//!   accepts (its `.git` a regular file naming an administrative folder in
//!   the repository's `worktrees`, whose `gitdir` leads back to the
//!   worktree and whose `commondir` to the repository's git directory),
//!   the control that each layout is the one it means to be;
//! - `read_layer` on the layer itself, the control that it is there and
//!   reads as the case says;
//! - `other_layers_fit`, which must answer what the review's model of
//!   Codex expects: unknown where Codex reads the malformed layer (the
//!   trusted repository's own; a worktree registered correctly, by an
//!   absolute or a relative pointer, its `.codex` or `config.toml` a link;
//!   a worktree inside the repository; one trusted by its own name; the
//!   repository's parent trusted), and a fit where it reads none (a
//!   benign layer, no layer, a registration naming another folder, a
//!   `.codex` that is Codex's own directory).
//!
//! The boundary, kept explicit: in five cases Codex reads no layer and
//! EnvCloak withholds the allowance (`network_settings_unknown`), because
//! it looks through every checkout a registration names, whether Codex
//! would accept that registration or not, and an explicitly untrusted
//! worktree of a trusted repository too (11: the worktree marked
//! untrusted; 13: a `commondir` naming another folder; 14: the
//! administrative folder a link; 15: the worktree's `.git` a link; 17: a
//! `.git` that is not a pointer). These fail closed: the test fails if any
//! of them is read as fitting (a check that would then also miss a valid
//! one), or if any case outside them differs from the model. Run twice:
//! as written, and with the four valid outside worktrees also trusted by
//! their own names (the same answers).
//!
//! Mutation checked: `linked_worktrees` not called (round 6): the valid
//! outside worktrees (3, 8, 9, 10) fit, and the gate fails.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use envcloak_agents::codex_layers::{Layer, other_layers_fit, read_layer};
use envcloak_agents::locations::Locations;

/// The cases where EnvCloak withholds the allowance and Codex would read
/// no layer.
const BOUNDARY: [u8; 5] = [11, 13, 14, 15, 17];

/// The cases where Codex reads the malformed layer.
const READ: [u8; 9] = [1, 3, 4, 5, 6, 8, 9, 10, 16];

/// The valid worktrees outside the repository (trusted by their own names
/// too in the second run).
const OUTSIDE: [u8; 4] = [3, 8, 9, 10];

/// A regular file's text (not a link, at most 64 KiB, UTF-8).
fn regular(p: &Path) -> Option<String> {
    let m = fs::symlink_metadata(p).ok()?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > 65_536 {
        return None;
    }
    String::from_utf8(fs::read(p).ok()?).ok()
}

/// Whether the worktree's registration is one Codex accepts: a fixture
/// graph mirroring the documented identity checks, not a call to Codex.
fn graph(repo: &Path, wt: &Path, owned: &Path) -> bool {
    let Some(pointer) = regular(&wt.join(".git")) else {
        return false;
    };
    let Some(target) = pointer.trim().strip_prefix("gitdir:") else {
        return false;
    };
    let admin = wt.join(target.trim());
    let Ok(m) = fs::symlink_metadata(&admin) else {
        return false;
    };
    if !m.is_dir() || m.file_type().is_symlink() {
        return false;
    }
    let Ok(a) = fs::canonicalize(admin) else {
        return false;
    };
    if !a.starts_with(owned)
        || a.parent()
            .and_then(Path::file_name)
            .is_none_or(|n| n != "worktrees")
    {
        return false;
    }
    let common = a.parent().unwrap().parent().unwrap();
    let (Some(back), Some(relative)) = (regular(&a.join("gitdir")), regular(&a.join("commondir")))
    else {
        return false;
    };
    let back = a.join(back.trim());
    if back.file_name().is_none_or(|n| n != ".git") {
        return false;
    }
    if fs::canonicalize(back.parent().unwrap()).ok() != fs::canonicalize(wt).ok()
        || fs::canonicalize(a.join(relative.trim())).ok().as_deref() != Some(common)
    {
        return false;
    }
    fs::canonicalize(repo.join(".git")).ok().as_deref() == Some(common)
}

/// What `other_layers_fit` answered: 0 fits, 1 another refusal, 2
/// unknown.
fn result(l: &Locations) -> u8 {
    match other_layers_fit(l) {
        Ok(()) => 0,
        Err(e) if e.name == "network_settings_unknown" => 2,
        Err(_) => 1,
    }
}

/// One case: the problems found, if any.
fn case(owned: &Path, id: u8, promote: bool) -> Vec<String> {
    let root = owned.join(format!("case-{id}"));
    let repo = root.join("repo");
    let home = root.join("home");
    let wt = if id == 5 {
        repo.join("linked")
    } else {
        root.join("linked")
    };
    let admin = repo.join(".git/worktrees/fixture");
    for p in [
        &repo,
        &home,
        &home.join(".codex"),
        &wt,
        &admin,
        &repo.join(".git/objects"),
        &repo.join(".git/refs/heads"),
        &root.join("system"),
        &root.join("managed"),
    ] {
        fs::create_dir_all(p).unwrap();
    }
    fs::write(repo.join(".git/HEAD"), b"ref: refs/heads/fixture\n").unwrap();
    fs::write(admin.join("HEAD"), b"ref: refs/heads/fixture\n").unwrap();
    fs::write(admin.join("commondir"), b"../..\n").unwrap();
    fs::write(
        admin.join("gitdir"),
        format!("{}\n", wt.join(".git").display()),
    )
    .unwrap();
    let target = if id == 8 {
        PathBuf::from("../repo/.git/worktrees/fixture")
    } else {
        admin.clone()
    };
    fs::write(wt.join(".git"), format!("gitdir: {}\n", target.display())).unwrap();
    match id {
        12 | 16 => {
            fs::write(
                admin.join("gitdir"),
                format!("{}\n", root.join("unrelated/.git").display()),
            )
            .unwrap();
        }
        13 => {
            fs::create_dir(root.join("unrelated")).unwrap();
            fs::write(
                admin.join("commondir"),
                format!("{}\n", root.join("unrelated").display()),
            )
            .unwrap();
        }
        14 => {
            fs::rename(&admin, root.join("admin-copy")).unwrap();
            symlink(root.join("admin-copy"), &admin).unwrap();
        }
        15 => {
            fs::rename(wt.join(".git"), wt.join("pointer-copy")).unwrap();
            symlink(wt.join("pointer-copy"), wt.join(".git")).unwrap();
        }
        17 => fs::write(wt.join(".git"), b"not a gitdir pointer\n").unwrap(),
        _ => {}
    }
    let mut problems = Vec::new();
    let valid = !(12..=17).contains(&id);
    if graph(&repo, &wt, owned) != valid {
        problems.push(format!("{id}: the fixture graph is not the layout's"));
    }
    let config_dir = if id <= 1 {
        repo.join(".codex")
    } else {
        wt.join(".codex")
    };
    let malformed = !matches!(id, 0 | 2 | 7 | 18);
    let contents = if malformed {
        "[unfinished"
    } else {
        "model = 'fixture'\n"
    };
    match id {
        7 => {}
        10 => {
            fs::create_dir(root.join("linked-config")).unwrap();
            fs::write(root.join("linked-config/config.toml"), contents).unwrap();
            symlink(root.join("linked-config"), &config_dir).unwrap();
        }
        18 => symlink(home.join(".codex"), &config_dir).unwrap(),
        9 => {
            fs::create_dir_all(&config_dir).unwrap();
            fs::write(root.join("config-copy"), contents).unwrap();
            symlink(root.join("config-copy"), config_dir.join("config.toml")).unwrap();
        }
        _ => {
            fs::create_dir_all(&config_dir).unwrap();
            fs::write(config_dir.join("config.toml"), contents).unwrap();
        }
    }
    let trusted = if id == 6 { root.clone() } else { repo.clone() };
    let mut user = format!(
        "[projects.\"{}\"]\ntrust_level = 'trusted'\n",
        trusted.display()
    );
    if id == 4 || id == 16 || (promote && OUTSIDE.contains(&id)) {
        user += &format!("[projects.\"{}\"]\ntrust_level = 'trusted'\n", wt.display());
    }
    if id == 11 {
        user += &format!(
            "[projects.\"{}\"]\ntrust_level = 'untrusted'\n",
            wt.display()
        );
    }
    fs::write(home.join(".codex/config.toml"), user).unwrap();
    // Nothing above the fixture holds a layer of its own.
    for a in root.ancestors().filter(|a| !a.starts_with(owned)) {
        assert!(fs::symlink_metadata(a.join(".codex/config.toml")).is_err());
    }
    let env = |k: &str| (k == "HOME").then(|| home.clone().into_os_string());
    let l = Locations::new(&env)
        .unwrap()
        .with_system_dirs(root.join("system"), root.join("managed"));
    let direct = match read_layer(&config_dir.join("config.toml")) {
        Layer::Absent => id == 7,
        Layer::Unreadable => malformed,
        Layer::Doc(_) => !malformed,
    };
    if !direct {
        problems.push(format!("{id}: the layer does not read as the case says"));
    }
    let expected = if READ.contains(&id) { 2 } else { 0 };
    let got = result(&l);
    let want = if BOUNDARY.contains(&id) { 2 } else { expected };
    if got != want {
        problems.push(format!(
            "{id}: answered {got}, not {want} (the model: {expected})"
        ));
    }
    problems
}

#[test]
fn trusted_worktrees_are_found_as_codex_finds_them() {
    for promote in [false, true] {
        let tmp = tempfile::Builder::new()
            .prefix("ec-cwo-")
            .tempdir_in("/tmp")
            .unwrap();
        let owned = fs::canonicalize(tmp.path()).unwrap();
        let problems: Vec<String> = (0..19).flat_map(|id| case(&owned, id, promote)).collect();
        assert!(problems.is_empty(), "promote {promote}: {problems:#?}");
    }
}
