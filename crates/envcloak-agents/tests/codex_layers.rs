//! Codex's settings as the pinned Codex merges its layers (Codex review,
//! round 6), through the public API with a catalog whose system and
//! managed-preferences directories are a fixture's:
//!
//! - the socket allowance's other layers (`other_layers_fit`): a network
//!   setting in the system, managed or requirements file, in a profile
//!   file, in a trusted project's `.codex/config.toml` (at its root, in a
//!   folder below it, or in a folder above it) refuses the allowance as
//!   `network_settings_present`; a device profile for Codex, a cache of an
//!   organization's settings, a layer that is not readable TOML, a folder
//!   of a trusted project that cannot be listed, or more folders than the
//!   budget refuse it as `network_settings_unknown`. Controls: no other
//!   layer, a project that is not trusted, layers with other settings,
//!   network access turned off, and Codex's own directory inside a trusted
//!   project (Codex does not read it as a project layer) all fit.
//! - the instruction settings (`doc_view`): a higher layer's
//!   `project_doc_fallback_filenames` replaces a lower one's (an empty
//!   list too), `project_doc_max_bytes` is the highest layer's, and the
//!   project root is found by `project_root_markers` from the layers below
//!   the projects' (a custom marker; none: the directory alone).
//!
//! Mutations checked: `other_layers_fit` answering `Ok` at once: every
//! refusal case fits and this fails. The trusted projects not looked
//! through (`walk` not called): the root, nested and budget cases fit and
//! this fails. The fallback lists joined again (each layer's names added
//! to the lower ones'): the replacement cases pick the user's file and this
//! fails. Markers ignored (`.git` alone): the custom-marker root is not
//! found and this fails.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use envcloak_agents::codex_layers::{
    doc_view, file_read_in, files_before, other_layers_fit, other_layers_fit_within,
};
use envcloak_agents::locations::Locations;
use envcloak_testkit::agents::finish_capped;

struct Fx {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Fx {
    fn new() -> Fx {
        let dir = tempfile::Builder::new()
            .prefix("eccl")
            .tempdir_in("/tmp")
            .unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        for d in ["home/.codex", "etc-codex", "prefs", "work"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        Fx { _dir: dir, root }
    }
    fn locations(&self) -> Locations {
        let home = self.root.join("home").into_os_string();
        let env = move |k: &str| (k == "HOME").then(|| home.clone());
        Locations::new(&env)
            .unwrap()
            .with_system_dirs(self.root.join("etc-codex"), self.root.join("prefs"))
    }
    fn write(&self, rel: &str, text: &str) -> PathBuf {
        let p = self.root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, text).unwrap();
        p
    }
    fn trust(&self, project: &Path, extra: &str) {
        self.write(
            "home/.codex/config.toml",
            &format!(
                "model = \"m\"\n{extra}\n[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
                project.display()
            ),
        );
    }
}

const RULE: &str = "[features.network_proxy.domains]\n\"127.0.0.1\" = \"allow\"\n";

fn refusal(l: &Locations) -> Option<String> {
    other_layers_fit(l).err().map(|r| r.name.to_owned())
}

#[test]
fn every_other_layer_is_read_before_the_socket_allowance_is_written() {
    let present = Some("network_settings_present".to_owned());
    let unknown = Some("network_settings_unknown".to_owned());
    let mut misses: Vec<String> = Vec::new();
    let mut expect = |name: &str, fx: &Fx, want: &Option<String>| {
        let got = refusal(&fx.locations());
        if &got != want {
            misses.push(format!("{name}: {got:?}, not {want:?}"));
        }
    };

    // Controls: nothing else, other settings, a project not trusted,
    // network access off, Codex's own directory inside a trusted project.
    let fx = Fx::new();
    expect("nothing else", &fx, &None);
    fx.write("etc-codex/config.toml", "model = \"m\"\n");
    fx.write("home/.codex/work.config.toml", "model = \"m\"\n");
    fx.write(
        "etc-codex/requirements.toml",
        "allowed_approval_policies = [\"on-request\"]\n",
    );
    fx.write("work/p/.codex/config.toml", RULE);
    fx.write("home/.codex/config.toml", "model = \"m\"\n");
    expect("other settings, an untrusted project", &fx, &None);
    let fx = Fx::new();
    fx.write(
        "work/q/.codex/config.toml",
        "[sandbox_workspace_write]\nnetwork_access = false\n",
    );
    fx.trust(&fx.root.join("work/q"), "");
    expect("network access off", &fx, &None);
    let fx = Fx::new();
    // `~` trusted: its `.codex` is Codex's own directory, whose config.toml
    // is the user's layer (and EnvCloak's), not a project's.
    fx.write("home/sub/x.txt", "x\n");
    fx.trust(
        &fx.root.join("home"),
        "[sandbox_workspace_write]\nnetwork_access = true\n",
    );
    expect("Codex's own directory", &fx, &None);

    // A network setting in each layer EnvCloak can read.
    for rel in [
        "etc-codex/config.toml",
        "etc-codex/managed_config.toml",
        "home/.codex/work.config.toml",
    ] {
        let fx = Fx::new();
        fx.write(rel, RULE);
        expect(rel, &fx, &present);
    }
    let fx = Fx::new();
    fx.write(
        "etc-codex/requirements.toml",
        "[network]\nallowed_domains = [\"example.com\"]\n",
    );
    expect("requirements", &fx, &present);
    let fx = Fx::new();
    fx.write(
        "etc-codex/config.toml",
        "[profiles.work.features.network_proxy]\nenabled = false\n",
    );
    expect("a system profile", &fx, &present);
    for (name, rel) in [
        ("a trusted project", "work/p/.codex/config.toml"),
        ("a folder below it", "work/p/a/b/.codex/config.toml"),
        ("a folder above it", "work/.codex/config.toml"),
    ] {
        let fx = Fx::new();
        std::fs::create_dir_all(fx.root.join("work/p/a/b")).unwrap();
        fx.write(rel, RULE);
        fx.trust(&fx.root.join("work/p"), "");
        expect(name, &fx, &present);
    }
    let fx = Fx::new();
    fx.write(
        "work/p/.codex/config.toml",
        "[features]\nnetwork_proxy = false\n",
    );
    fx.trust(&fx.root.join("work/p"), "");
    expect("the proxy turned off in a project", &fx, &present);

    // What may hold one and cannot be read.
    let fx = Fx::new();
    fx.write("prefs/com.openai.codex.plist", "x");
    expect("a device profile", &fx, &unknown);
    let fx = Fx::new();
    fx.write("prefs/someone/com.openai.codex.plist", "x");
    expect("a device profile for one user", &fx, &unknown);
    let fx = Fx::new();
    fx.write("home/.codex/cloud-config-bundle-cache.json", "{}");
    expect("an organization's settings", &fx, &unknown);
    let fx = Fx::new();
    fx.write("etc-codex/managed_config.toml", "not = = toml");
    expect("a layer that is not TOML", &fx, &unknown);
    let fx = Fx::new();
    let locked = fx.root.join("work/p/locked");
    std::fs::create_dir_all(&locked).unwrap();
    fx.trust(&fx.root.join("work/p"), "");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let listable = std::fs::read_dir(&locked).is_ok();
    if listable {
        eprintln!("skipped the unlistable case: the folder can still be listed (root)");
    } else {
        expect("a folder that cannot be listed", &fx, &unknown);
    }
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    // More folders than the budget.
    let fx = Fx::new();
    for i in 0..12 {
        std::fs::create_dir_all(fx.root.join(format!("work/p/d{i}"))).unwrap();
    }
    fx.trust(&fx.root.join("work/p"), "");
    let l = fx.locations();
    let small = other_layers_fit_within(&l, 5)
        .err()
        .map(|r| r.name.to_owned());
    if small != unknown {
        misses.push(format!("over the budget: {small:?}"));
    }
    if other_layers_fit_within(&l, 50).is_err() {
        misses.push("within the budget: refused".to_owned());
    }
    assert!(misses.is_empty(), "{misses:#?}");
}

/// `git <args>` in `dir`, with a cleared environment and no user or system
/// configuration, within a bound (`finish_capped`); it must succeed.
fn git(dir: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    cmd.args([
        "-c",
        "user.name=EnvCloak test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "init.defaultBranch=main",
        "-c",
        "core.hooksPath=/dev/null",
    ])
    .args(args)
    .current_dir(dir)
    .env_clear()
    .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
    .env("HOME", dir)
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("LC_ALL", "C")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let out = finish_capped(cmd, Duration::from_secs(60), 1 << 20);
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The verifier's round-6 finding (Codex F-128) and its class: a folder
/// whose project layer Codex reads and the check did not. Each case is
/// one trusted project's layout:
///
/// - a folder link inside the project to a folder whose `.codex` holds a
///   domain rule fits: a session named through the link reads that layer,
///   but runs no command in Codex's `workspace-write` sandbox (measured on
///   the pinned Codex in `m2_story`), and a session Codex starts itself is
///   in a resolved path; a link that loops back and one that leads
///   nowhere fit too;
/// - a linked git worktree of the project (made by git), outside it, with
///   the rule in its own `.codex/config.toml`: Codex trusts the worktree
///   through its main checkout, so it is present; controls: the same
///   worktree without the rule, and a worktree of a repository that is not
///   trusted, with the rule, both fit;
/// - a project trusted in a profile file only (a session under
///   `--profile` trusts it), holding the rule: present;
/// - `project_root_markers` with a marker other than `.git` puts the root
///   above a checkout, where the folders above are checked: a rule there
///   is present, and with none the project fits;
/// - a `.codex` that is a file above the project: Codex reads no layer
///   there, so it fits (the check had read it as unreadable);
/// - a `.codex` above the project that is a link to Codex's own directory,
///   whose `config.toml` holds the allowance as written: the user's layer,
///   not a project's, so it fits;
/// - a project named through a link to a deeper folder, with the rule in a
///   folder above where the link leads: present;
/// - a device profile in a user folder that is a link: unknown.
///
/// Mutations checked, each failing here for its case: `linked_worktrees`
/// not called; profile files not read for trusted projects; the folders
/// above a checkout not checked (`check_dir` skipped for them); Codex's
/// own directory compared by its name only; the ancestors of where a
/// project's name leads not checked; the managed preferences' user entries
/// taken only when they are real folders.
#[test]
fn linked_folders_worktrees_and_profiles_are_read_as_codex_reads_them() {
    let present = Some("network_settings_present".to_owned());
    let unknown = Some("network_settings_unknown".to_owned());
    let mut misses: Vec<String> = Vec::new();
    let mut expect = |name: &str, fx: &Fx, want: &Option<String>| {
        let got = refusal(&fx.locations());
        if &got != want {
            misses.push(format!("{name}: {got:?}, not {want:?}"));
        }
    };

    // A folder link inside the project.
    let fx = Fx::new();
    fx.write("elsewhere/.codex/config.toml", RULE);
    std::fs::create_dir_all(fx.root.join("work/p")).unwrap();
    std::os::unix::fs::symlink(fx.root.join("elsewhere"), fx.root.join("work/p/link")).unwrap();
    fx.trust(&fx.root.join("work/p"), "");
    expect("a folder link in the project", &fx, &None);
    let fx = Fx::new();
    std::fs::create_dir_all(fx.root.join("work/p/a")).unwrap();
    std::os::unix::fs::symlink(fx.root.join("work/p"), fx.root.join("work/p/a/up")).unwrap();
    std::os::unix::fs::symlink(fx.root.join("nowhere"), fx.root.join("work/p/gone")).unwrap();
    fx.trust(&fx.root.join("work/p"), "");
    expect("a loop and a link to nothing", &fx, &None);

    // A linked worktree, made by git, outside the trusted checkout.
    for (name, trusted, rule, want) in [
        ("a worktree of the project", true, true, &present),
        ("the worktree, no rule", true, false, &None),
        ("a worktree of a project not trusted", false, true, &None),
    ] {
        let fx = Fx::new();
        let main = fx.root.join("work/main");
        std::fs::create_dir_all(&main).unwrap();
        git(&main, &["init", "-q"]);
        git(&main, &["commit", "-q", "--allow-empty", "-m", "start"]);
        let wt = fx.root.join("trees/wt");
        git(&main, &["worktree", "add", "-q", wt.to_str().unwrap()]);
        if rule {
            fx.write("trees/wt/.codex/config.toml", RULE);
        }
        if trusted {
            fx.trust(&main, "");
        } else {
            fx.trust(&fx.root.join("work/other"), "");
        }
        expect(name, &fx, want);
    }

    // Trusted in a profile file only.
    let fx = Fx::new();
    fx.write("work/q/.codex/config.toml", RULE);
    fx.write(
        "home/.codex/work.config.toml",
        &format!(
            "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
            fx.root.join("work/q").display()
        ),
    );
    expect("trusted in a profile file", &fx, &present);

    // Markers.
    for (rule, want) in [(true, &present), (false, &None)] {
        let fx = Fx::new();
        std::fs::create_dir_all(fx.root.join("work/r/.hg")).unwrap();
        std::fs::create_dir_all(fx.root.join("work/r/p/.git")).unwrap();
        if rule {
            fx.write("work/r/.codex/config.toml", RULE);
        }
        fx.trust(
            &fx.root.join("work/r/p"),
            "project_root_markers = [\".hg\"]",
        );
        expect(&format!("a root above by .hg, rule {rule}"), &fx, want);
    }

    // Above the project: a `.codex` file, and a link to Codex's own
    // directory while the user's file holds the allowance.
    let fx = Fx::new();
    std::fs::create_dir_all(fx.root.join("work/p")).unwrap();
    fx.write("work/.codex", "not a folder\n");
    fx.trust(&fx.root.join("work/p"), "");
    expect("a .codex file above", &fx, &None);
    let fx = Fx::new();
    std::fs::create_dir_all(fx.root.join("work/p")).unwrap();
    std::os::unix::fs::symlink(fx.root.join("home/.codex"), fx.root.join("work/.codex")).unwrap();
    fx.trust(
        &fx.root.join("work/p"),
        "[sandbox_workspace_write]\nnetwork_access = true\n",
    );
    expect("Codex's own directory linked above", &fx, &None);

    // A project named through a link to a deeper folder: the folders above
    // where it leads.
    let fx = Fx::new();
    std::fs::create_dir_all(fx.root.join("deep/a/b/p")).unwrap();
    fx.write("deep/a/.codex/config.toml", RULE);
    std::os::unix::fs::symlink(fx.root.join("deep/a/b"), fx.root.join("named")).unwrap();
    fx.trust(&fx.root.join("named/p"), "");
    expect("above where a project's name leads", &fx, &present);

    // A device profile in a user folder that is a link.
    let fx = Fx::new();
    fx.write("profiles/someone/com.openai.codex.plist", "x");
    std::os::unix::fs::symlink(
        fx.root.join("profiles/someone"),
        fx.root.join("prefs/someone"),
    )
    .unwrap();
    expect("a device profile through a link", &fx, &unknown);

    assert!(misses.is_empty(), "{misses:#?}");
}

#[test]
fn the_instruction_settings_are_the_merged_ones() {
    let mut misses: Vec<String> = Vec::new();
    // A project's list replaces the user's; both candidate files are there.
    let fx = Fx::new();
    fx.write(
        "home/.codex/config.toml",
        "project_doc_fallback_filenames = [\"USER.md\"]\nproject_doc_max_bytes = 4096\n",
    );
    let p = fx.root.join("work/p");
    std::fs::create_dir_all(p.join(".git")).unwrap();
    fx.write(
        "work/p/.codex/config.toml",
        "project_doc_fallback_filenames = [\"PROJECT.md\"]\nproject_doc_max_bytes = 9000\n",
    );
    fx.write("work/p/USER.md", "# user\n");
    fx.write("work/p/PROJECT.md", "# project\n");
    let l = fx.locations();
    let v = doc_view(&l, &p);
    if v.fallbacks != ["PROJECT.md"] || v.limit != 9000 {
        misses.push(format!("project over user: {v:?}"));
    }
    if file_read_in(&p, &v.fallbacks) != Some(p.join("PROJECT.md")) {
        misses.push(format!("file read: {:?}", file_read_in(&p, &v.fallbacks)));
    }
    // An empty list replaces it too: Codex reads neither, a new AGENTS.md.
    fx.write(
        "work/p/.codex/config.toml",
        "project_doc_fallback_filenames = []\n",
    );
    let v = doc_view(&l, &p);
    if !v.fallbacks.is_empty() || v.limit != 4096 {
        misses.push(format!("an empty list: {v:?}"));
    }
    // The managed file is above every other.
    fx.write(
        "etc-codex/managed_config.toml",
        "project_doc_fallback_filenames = [\"MANAGED.md\"]\n",
    );
    if doc_view(&l, &p).fallbacks != ["MANAGED.md"] {
        misses.push("managed".to_owned());
    }

    // Markers: a custom one finds the root above (and its files are read
    // first); `.git` alone would not.
    let fx = Fx::new();
    fx.write(
        "home/.codex/config.toml",
        "project_root_markers = [\".hg\"]\n",
    );
    std::fs::create_dir_all(fx.root.join("work/r/.hg")).unwrap();
    let sub = fx.root.join("work/r/s/t");
    std::fs::create_dir_all(&sub).unwrap();
    fx.write("work/r/AGENTS.md", "# root\n");
    fx.write("work/r/s/AGENTS.md", "# s\n");
    let l = fx.locations();
    let v = doc_view(&l, &sub);
    if v.root.as_deref() != Some(fx.root.join("work/r").as_path()) {
        misses.push(format!("custom marker: {v:?}"));
    }
    let before = files_before(&v, &sub);
    if before
        != [
            fx.root.join("work/r/AGENTS.md"),
            fx.root.join("work/r/s/AGENTS.md"),
        ]
    {
        misses.push(format!("files before: {before:?}"));
    }
    // A project layer's markers are not read (Codex reads them from the
    // layers below the projects' only).
    fx.write(
        "work/r/s/t/.codex/config.toml",
        "project_root_markers = []\n",
    );
    if doc_view(&l, &sub).root.is_none() {
        misses.push("a project's markers were read".to_owned());
    }
    // No markers: the directory alone.
    fx.write("home/.codex/config.toml", "project_root_markers = []\n");
    let v = doc_view(&l, &sub);
    if v.root.is_some() || !files_before(&v, &sub).is_empty() {
        misses.push(format!("no markers: {v:?}"));
    }
    assert!(misses.is_empty(), "{misses:#?}");
}
