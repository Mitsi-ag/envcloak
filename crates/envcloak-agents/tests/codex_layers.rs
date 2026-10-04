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
/// configuration, within a bound (`finish_capped`); it must succeed, and
/// what it printed is returned.
fn git(dir: &Path, args: &[&str]) -> String {
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
    String::from_utf8(out.stdout).unwrap()
}

/// A repository at `main` whose git directory is elsewhere, with a linked
/// worktree at `wt` (both made by git): `separate` puts it beside the
/// checkout (`git init --separate-git-dir`, `main/.git` a file naming
/// it); otherwise `main/.bare` is a bare repository and `main/.git` the
/// pointer `gitdir: ./.bare`, the layout worktree workflows use. Returns
/// the git directory.
fn elsewhere_git_dir(root: &Path, main: &Path, wt: &Path, separate: bool) -> PathBuf {
    std::fs::create_dir_all(main).unwrap();
    if separate {
        let gd = root.join("gitdata");
        git(
            main,
            &["init", "-q", "--separate-git-dir", gd.to_str().unwrap()],
        );
        git(main, &["commit", "-q", "--allow-empty", "-m", "start"]);
        git(main, &["worktree", "add", "-q", wt.to_str().unwrap()]);
        gd
    } else {
        git(main, &["init", "-q", "--bare", ".bare"]);
        std::fs::write(main.join(".git"), "gitdir: ./.bare\n").unwrap();
        let tree = git(main, &["mktree"]);
        let commit = git(main, &["commit-tree", tree.trim(), "-m", "start"]);
        git(main, &["update-ref", "refs/heads/main", commit.trim()]);
        git(
            main,
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "w",
                wt.to_str().unwrap(),
                "main",
            ],
        );
        main.join(".bare")
    }
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

/// The verifier's round-7 finding (low): a repository whose `.git` is a
/// file naming its git directory elsewhere has its worktrees registered
/// there, and the pinned Codex trusts them through the main checkout
/// (`trust.rs` reads the pointer). Two layouts made by git: a separate git
/// directory (`git init --separate-git-dir`) and a bare repository with a
/// `gitdir: ./.bare` pointer; in each, the worktree outside the checkout
/// holding a domain rule is present, and without the rule it fits.
///
/// Mutation checked: the pointer not followed in `linked_worktrees`
/// (`(!t.is_empty() && false).then(..)`): both present cases fit and this
/// fails.
#[test]
fn a_git_directory_named_by_a_pointer_has_its_worktrees_read() {
    let mut misses: Vec<String> = Vec::new();
    for separate in [true, false] {
        for rule in [true, false] {
            let fx = Fx::new();
            let main = fx.root.join("work/main");
            let wt = fx.root.join("trees/wt");
            let gd = elsewhere_git_dir(&fx.root, &main, &wt, separate);
            assert!(std::fs::metadata(main.join(".git")).unwrap().is_file());
            assert!(gd.join("worktrees").is_dir(), "{}", gd.display());
            if rule {
                fx.write("trees/wt/.codex/config.toml", RULE);
            }
            fx.trust(&main, "");
            let want = rule.then(|| "network_settings_present".to_owned());
            let got = refusal(&fx.locations());
            if got != want {
                misses.push(format!(
                    "separate {separate}, rule {rule}: {got:?}, not {want:?}"
                ));
            }
        }
    }
    assert!(misses.is_empty(), "{misses:#?}");
}

/// The verifier's round-7 finding (low) and its class: every place whose
/// failure to be read withholds the socket allowance
/// (`network_settings_unknown`), each tested, where before only an
/// unlistable folder of a trusted project was:
///
/// - the managed preferences, searchable and not listable, and a user
///   folder in them that cannot be searched;
/// - Codex's directory, searchable and not listable (its profile files);
/// - a separate git directory's `worktrees`, not listable; a worktree's
///   entry there that cannot be searched; its `gitdir` file that cannot be
///   opened; a checkout's `.git` that is a link to itself;
/// - a layer in a directory that cannot be searched, a layer that is a
///   folder, one larger than EnvCloak reads, one that cannot be opened,
///   one that is not UTF-8, and the user's `config.toml` that is not TOML;
/// - a folder of a trusted project that can be listed and not searched.
///
/// Skipped as root, where permissions do not hold. Mutations checked, each
/// failing here for its case: the preferences' listing error read as no
/// entries (`codex_managed_preferences`); a user folder's error read as
/// absent (`exists`); Codex's directory's listing error read as no
/// profiles (`codex_profile_configs`); the registry's listing error, the
/// entry's error and the `gitdir` file's open error read as no worktree;
/// `.git`'s error read as no repository (`linked_worktrees`); a layer's
/// `metadata`, `open` and UTF-8 errors read as absent (`read_layer`); the
/// user's unreadable file read as no opt-out (`symlinked_home_allowed`);
/// a folder's `metadata` error skipped (`walk`).
#[test]
fn every_place_that_cannot_be_read_withholds_the_allowance() {
    use std::fs::Permissions;
    let unknown = Some("network_settings_unknown".to_owned());
    let misses: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
    // Whether permissions hold for this process (not as root).
    let probe = Fx::new();
    let locked = probe.root.join("work/locked");
    std::fs::create_dir_all(&locked).unwrap();
    std::fs::set_permissions(&locked, Permissions::from_mode(0o000)).unwrap();
    let held = std::fs::read_dir(&locked).is_err();
    std::fs::set_permissions(&locked, Permissions::from_mode(0o700)).unwrap();
    if !held {
        eprintln!("skipped: permissions do not hold for this process (root)");
        return;
    }
    // `mode` on `path` while the check runs, then back to `0o700` (or
    // `0o600` for a file).
    let case = |name: &str, fx: &Fx, path: &Path, mode: u32| {
        let file = std::fs::metadata(path).unwrap().is_file();
        std::fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
        let got = refusal(&fx.locations());
        let back = if file { 0o600 } else { 0o700 };
        std::fs::set_permissions(path, Permissions::from_mode(back)).unwrap();
        if got != unknown {
            misses.borrow_mut().push(format!("{name}: {got:?}"));
        }
    };

    let fx = Fx::new();
    case(
        "the managed preferences not listable",
        &fx,
        &fx.root.join("prefs"),
        0o300,
    );
    let fx = Fx::new();
    std::fs::create_dir_all(fx.root.join("prefs/someone")).unwrap();
    case(
        "a user folder in the managed preferences not searchable",
        &fx,
        &fx.root.join("prefs/someone"),
        0o000,
    );
    let fx = Fx::new();
    case(
        "Codex's directory not listable",
        &fx,
        &fx.root.join("home/.codex"),
        0o300,
    );

    // A separate git directory, outside the trusted checkout (so the
    // checkout's own walk does not meet it).
    let fx = Fx::new();
    let main = fx.root.join("work/main");
    let wt = fx.root.join("trees/wt");
    let gd = elsewhere_git_dir(&fx.root, &main, &wt, true);
    fx.write("trees/wt/.codex/config.toml", RULE);
    fx.trust(&main, "");
    case(
        "a separate git directory's worktrees not listable",
        &fx,
        &gd.join("worktrees"),
        0o300,
    );
    case(
        "a worktree's entry not searchable",
        &fx,
        &gd.join("worktrees/wt"),
        0o000,
    );
    case(
        "a worktree's gitdir file not readable",
        &fx,
        &gd.join("worktrees/wt/gitdir"),
        0o000,
    );
    let fx = Fx::new();
    std::fs::create_dir_all(fx.root.join("work/p")).unwrap();
    std::os::unix::fs::symlink(fx.root.join("work/p/.git"), fx.root.join("work/p/.git")).unwrap();
    fx.trust(&fx.root.join("work/p"), "");
    if refusal(&fx.locations()) != unknown {
        misses
            .borrow_mut()
            .push("a .git that is a link to itself".to_owned());
    }

    // Layers.
    let fx = Fx::new();
    fx.write("etc-codex/config.toml", "model = \"m\"\n");
    case(
        "the system directory not searchable",
        &fx,
        &fx.root.join("etc-codex"),
        0o000,
    );
    case(
        "a layer that cannot be opened",
        &fx,
        &fx.root.join("etc-codex/config.toml"),
        0o000,
    );
    let fx = Fx::new();
    std::fs::create_dir_all(fx.root.join("etc-codex/config.toml")).unwrap();
    if refusal(&fx.locations()) != unknown {
        misses
            .borrow_mut()
            .push("a layer that is a folder".to_owned());
    }
    let fx = Fx::new();
    let mut big = "model = \"m\"\n".to_owned();
    big.push_str(&"#".repeat(1024 * 1024));
    fx.write("etc-codex/managed_config.toml", &big);
    if refusal(&fx.locations()) != unknown {
        misses
            .borrow_mut()
            .push("a layer larger than EnvCloak reads".to_owned());
    }
    let fx = Fx::new();
    let p = fx.root.join("etc-codex/requirements.toml");
    std::fs::write(&p, b"model = \"\xff\"\n").unwrap();
    if refusal(&fx.locations()) != unknown {
        misses
            .borrow_mut()
            .push("a layer that is not UTF-8".to_owned());
    }
    let fx = Fx::new();
    fx.write("home/.codex/config.toml", "not = = toml\n");
    if refusal(&fx.locations()) != unknown {
        misses
            .borrow_mut()
            .push("the user's config.toml not TOML".to_owned());
    }

    // A folder of a trusted project listed and not searched.
    let fx = Fx::new();
    std::fs::create_dir_all(fx.root.join("work/p/s/in")).unwrap();
    fx.trust(&fx.root.join("work/p"), "");
    case(
        "a folder that can be listed and not searched",
        &fx,
        &fx.root.join("work/p/s"),
        0o400,
    );

    let misses = misses.into_inner();
    assert!(misses.is_empty(), "{misses:#?}");
}

/// The verifier's round-7 finding, measured on the pinned Codex in
/// `m2_story`: with `allow_symlinked_codex_home = true` in the user's
/// `config.toml`, a session named through a folder link at or beneath
/// Codex's directory runs its commands, and reads the layer of the folder
/// the link leads to. With the key, every folder Codex's directory leads
/// to is checked, links followed, trusted or not:
///
/// - a trusted project in Codex's directory, with a folder link to a
///   folder whose `.codex` holds a domain rule: present; controls: the
///   same without the key, with the key `false`, and with the key and no
///   rule, all fit;
/// - two links in a row, and a link straight from Codex's directory with
///   nothing trusted: present (the walk does not work out which folder a
///   link makes trusted);
/// - a folder of a trusted project walked first without links (the
///   project's own walk), then reached from Codex's directory through a
///   link, whose own folder link leads to the rule: present;
/// - Codex's directory itself a link (its name and where it leads both
///   walked), a loop and a link to nothing beside it: fit without a rule;
/// - a link to a folder that cannot be listed: unknown;
/// - a value that is not a boolean: counted as set (Codex refuses the
///   file), present.
///
/// Mutations checked, each failing here: the key not read
/// (`symlinked_home_allowed` answering `false`): the present cases fit;
/// links not followed in Codex's directory (`walk` pushing folders only):
/// the same; the seen-set keyed without the way of walking: the folder
/// walked first without links is skipped and its link's rule missed.
#[test]
fn with_the_symlinked_home_opt_out_every_folder_codex_home_leads_to_is_read() {
    let present = Some("network_settings_present".to_owned());
    let unknown = Some("network_settings_unknown".to_owned());
    let key = "allow_symlinked_codex_home = true";
    let mut misses: Vec<String> = Vec::new();
    let mut expect = |name: &str, fx: &Fx, want: &Option<String>| {
        let got = refusal(&fx.locations());
        if &got != want {
            misses.push(format!("{name}: {got:?}, not {want:?}"));
        }
    };
    let link = |fx: &Fx, to: &str, at: &str| {
        let at = fx.root.join(at);
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(fx.root.join(to), at).unwrap();
    };

    // The verifier's layout, and its controls.
    for (name, extra, rule, want) in [
        ("the opt-out, a rule behind the link", key, true, &present),
        ("no opt-out (control)", "", true, &None),
        (
            "the opt-out false (control)",
            "allow_symlinked_codex_home = false",
            true,
            &None,
        ),
        ("the opt-out, no rule (control)", key, false, &None),
        (
            "a value that is not a boolean",
            "allow_symlinked_codex_home = \"yes\"",
            true,
            &present,
        ),
    ] {
        let fx = Fx::new();
        std::fs::create_dir_all(fx.root.join("home/.codex/proj/.git")).unwrap();
        if rule {
            fx.write("work/elsewhere/.codex/config.toml", RULE);
        } else {
            fx.write("work/elsewhere/.codex/config.toml", "model = \"m\"\n");
        }
        link(&fx, "work/elsewhere", "home/.codex/proj/link");
        fx.trust(&fx.root.join("home/.codex/proj"), extra);
        expect(name, &fx, want);
    }

    // Two links in a row; a link from Codex's directory, nothing trusted.
    let fx = Fx::new();
    fx.write("work/far/.codex/config.toml", RULE);
    link(&fx, "work/far", "work/mid/on");
    link(&fx, "work/mid", "home/.codex/proj/first");
    fx.trust(&fx.root.join("home/.codex/proj"), key);
    expect("two links in a row", &fx, &present);
    let fx = Fx::new();
    fx.write("work/far/.codex/config.toml", RULE);
    link(&fx, "work/far", "home/.codex/l");
    fx.write("home/.codex/config.toml", &format!("{key}\n"));
    expect(
        "a link from Codex's directory, nothing trusted",
        &fx,
        &present,
    );

    // A trusted project's folder walked first without links, then reached
    // through a link from Codex's directory.
    let fx = Fx::new();
    fx.write("work/far/.codex/config.toml", RULE);
    link(&fx, "work/far", "work/p/sub/on");
    link(&fx, "work/p", "home/.codex/to-p");
    fx.trust(&fx.root.join("work/p"), key);
    expect("a folder walked twice", &fx, &present);
    // Control: without the key, the project's own walk takes no link.
    fx.trust(&fx.root.join("work/p"), "");
    expect("a folder walked once (control)", &fx, &None);

    // Codex's directory a link; a loop and a link to nothing in it.
    let fx = Fx::new();
    std::fs::remove_dir(fx.root.join("home/.codex")).unwrap();
    std::fs::create_dir_all(fx.root.join("data/codex/a")).unwrap();
    link(&fx, "data/codex", "home/.codex");
    link(&fx, "data/codex", "data/codex/a/up");
    link(&fx, "nowhere", "data/codex/gone");
    fx.trust(&fx.root.join("work/p"), key);
    std::fs::create_dir_all(fx.root.join("work/p")).unwrap();
    expect(
        "Codex's directory a link, a loop, a link to nothing",
        &fx,
        &None,
    );
    fx.write("work/far/.codex/config.toml", RULE);
    link(&fx, "work/far", "data/codex/a/far");
    expect(
        "Codex's directory a link, a rule behind a link",
        &fx,
        &present,
    );

    // A link to a folder that cannot be listed.
    let fx = Fx::new();
    let locked = fx.root.join("work/locked");
    std::fs::create_dir_all(locked.join("in")).unwrap();
    link(&fx, "work/locked", "home/.codex/l");
    fx.write("home/.codex/config.toml", &format!("{key}\n"));
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&locked).is_ok() {
        eprintln!("skipped the unlistable case: the folder can still be listed (root)");
    } else {
        expect("a link to a folder that cannot be listed", &fx, &unknown);
    }
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();

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
