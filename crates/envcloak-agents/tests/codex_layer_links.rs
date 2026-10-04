//! An independent check of the socket allowance's layer walk against how
//! the pinned Codex reads a project's layer (Codex F-128; rust-v0.159.2
//! `discover_project_layers`: a folder's `.codex` is looked at through a
//! symlink, skipped when it is Codex's own directory by name or by where
//! it leads, and its `config.toml` read), adopted unchanged in its cases
//! from the review's gate.
//!
//! Eight layouts of one trusted project, each read two ways: by
//! `read_layer` on the project's `.codex/config.toml` (the reader follows
//! the link, as Codex does: the positive control for every layout) and by
//! `other_layers_fit`, which must answer what that layer holds: nothing
//! (absent, a benign layer), `network_settings_unknown` (a layer that is
//! not TOML) or `network_settings_present` (the proxy feature named), the
//! same whether `.codex` is a folder, holds a linked file, or is itself a
//! link to a folder. A ninth: the project's `.codex` is a link to Codex's
//! own directory, whose `config.toml` (the user's, holding a network
//! setting here) is not a project layer, and fits.
//!
//! Mutation checked: the walk looking at `.codex` without following a
//! symlink (the round-6 `DirEntry::file_type` test, here
//! `symlink_metadata` in `dot_codex`): the three folder-link layouts fit,
//! two of them wrongly, and the gate fails. Codex's own directory compared
//! by its name only: the ninth layout reads the user's file as a project
//! layer, is refused as present, and fails.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use envcloak_agents::codex_layers::{Layer, other_layers_fit, read_layer};
use envcloak_agents::locations::Locations;

/// What `other_layers_fit` answered: 0 fits, 1 present, 2 unknown, 3 any
/// other refusal.
fn observed(l: &Locations) -> u8 {
    match other_layers_fit(l) {
        Ok(()) => 0,
        Err(e) if e.name == "network_settings_present" => 1,
        Err(e) if e.name == "network_settings_unknown" => 2,
        Err(_) => 3,
    }
}

/// One layout: whether the reader reads the project's layer as expected
/// (the control), what `other_layers_fit` should answer, and what it did.
fn fixture(kind: u8) -> (bool, u8, u8) {
    let tmp = tempfile::Builder::new()
        .prefix("ec-cll-")
        .tempdir_in("/tmp")
        .unwrap();
    let r = fs::canonicalize(tmp.path()).unwrap();
    let home = r.join("home");
    let project = r.join("project");
    let target = r.join("owned-config");
    for p in [
        &home,
        &project,
        &target,
        &r.join("system"),
        &r.join("managed"),
    ] {
        fs::create_dir_all(p).unwrap();
    }
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::write(
        home.join(".codex/config.toml"),
        format!(
            "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
            project.display()
        ),
    )
    .unwrap();
    // Nothing above the fixture is a layer of its own.
    for a in project.ancestors().filter(|a| !a.starts_with(&r)) {
        assert!(fs::symlink_metadata(a.join(".codex")).is_err(), "{a:?}");
    }
    let contents = match kind {
        2 | 6 => "this is not toml",
        3 | 4 | 7 => "[features]\nnetwork_proxy = false\n",
        _ => "model = \"inert\"\n",
    };
    let expected = match kind {
        2 | 6 => 2,
        3 | 4 | 7 => 1,
        _ => 0,
    };
    let active = project.join(".codex/config.toml");
    if kind != 0 {
        fs::write(target.join("config.toml"), contents).unwrap();
        if kind == 8 {
            fs::write(
                home.join(".codex/config.toml"),
                format!(
                    "[features]\nnetwork_proxy = false\n[projects.\"{}\"]\ntrust_level = \
                     \"trusted\"\n",
                    project.display()
                ),
            )
            .unwrap();
            symlink(home.join(".codex"), project.join(".codex")).unwrap();
        } else if kind >= 5 {
            symlink(&target, project.join(".codex")).unwrap();
        } else {
            fs::create_dir(project.join(".codex")).unwrap();
            if kind == 4 {
                symlink(target.join("config.toml"), &active).unwrap();
            } else {
                fs::write(&active, contents).unwrap();
            }
        }
    }
    let follows = match kind {
        0 => matches!(read_layer(&active), Layer::Absent),
        2 | 6 => matches!(read_layer(&active), Layer::Unreadable),
        _ => matches!(read_layer(&active), Layer::Doc(_)),
    };
    let env = |k: &str| (k == "HOME").then(|| home.clone().into_os_string());
    let l = Locations::new(&env)
        .unwrap()
        .with_system_dirs(r.join("system"), r.join("managed"));
    let got = observed(&l);
    let rp: PathBuf = r.clone();
    tmp.close().unwrap();
    assert!(!rp.exists());
    (follows, expected, got)
}

#[test]
fn linked_config_layers_are_counted_before_tree_links_are_skipped() {
    let rows: Vec<(u8, bool, u8, u8)> = (0..8)
        .map(|n| {
            let (follows, want, got) = fixture(n);
            (n, follows, want, got)
        })
        .collect();
    let mismatch = rows.iter().filter(|(_, f, w, g)| !*f || w != g).count();
    let controls = rows[..6].iter().filter(|(_, f, w, g)| *f && w == g).count();
    assert_eq!(controls, 6, "{rows:?}");
    assert_eq!(mismatch, 0, "layer coverage acceptance gate: {rows:?}");
}

#[test]
fn a_link_to_codex_home_is_the_user_layer_not_an_extra_project_layer() {
    let (follows, want, got) = fixture(8);
    assert!(follows);
    assert_eq!(want, 0);
    assert_eq!(got, want);
}
