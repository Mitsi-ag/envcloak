//! `envcloak ref` against the manifest, as the built CLI runs it in an
//! isolated home whose daemon's vault is unlocked (docs/MANIFEST.md
//! "Adding a binding": `ref` writes only a binding the daemon checked;
//! tests/login_refs.rs has it refused without one):
//!
//! - a variable named like a profile (`ref short=...` when `[env.short]`
//!   exists, as a table or with dotted keys) is refused, and the manifest
//!   keeps the profile and every binding;
//! - a manifest with another hard link is left alone, both names as they
//!   were;
//! - a replaced reference shaped like a key is hidden in the text and in
//!   `--json` alike;
//! - the manifest's path is shown whole, even under a directory named like
//!   a hash.
//!
//! Every output is swept for the generated tokens where they must not be.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::Path;
use std::process::Output;
use std::time::Duration;

use common::{
    cli_command, finish_within, outside_dir, run_on_terminal, secret_file, seed_vault,
    start_daemon, stderr, stdout,
};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

/// Placeholder the CLI prints in place of a name shaped like a key.
const HIDDEN: &str = "[not shown: looks like a key or token]";

/// A test home with a vault and its daemon, the vault unlocked by the
/// person on a terminal of their own (so run outside an agent's process
/// tree, whose unlock is refused).
fn unlocked_home() -> (TestHome, Daemon) {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    seed_vault(&home, &cs);
    let d = start_daemon(&home);
    let files = outside_dir();
    let pass = secret_file(
        files.path(),
        "pass",
        by_label(&cs, labels::VAULT_PASSPHRASE).value(),
    );
    let out = run_on_terminal(
        &home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
    );
    assert!(out.status.success(), "{}{}", stderr(&out), d.log());
    (home, d)
}

/// `envcloak <args>` with the working directory `dir`.
fn ref_in(home: &TestHome, dir: &Path, args: &[&str]) -> Output {
    let mut cmd = cli_command(home, args, &[]);
    cmd.current_dir(dir);
    finish_within(cmd, Duration::from_secs(60))
}

/// `n` lowercase hex digits from a fresh seed: a valid slug or directory
/// name, shaped like a token.
fn hex(n: usize) -> String {
    let mut x = fresh_seed();
    (0..n)
        .map(|_| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            char::from(b"0123456789abcdef"[usize::try_from(x >> 60).unwrap()])
        })
        .collect()
}

#[test]
fn a_variable_named_like_a_profile_is_refused_and_the_profile_kept() {
    let (home, _d) = unlocked_home();
    for text in [
        "[env]\nA = \"a/b\"\n\n[env.short]\nS = \"s/t\"\nT = \"u/v\"\n",
        "[env]\nA = \"a/b\"\nshort.S = \"s/t\"\nshort.T = \"u/v\"\n",
    ] {
        let dir = home.root().join("profile-name");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("envcloak.toml"), text).unwrap();
        let o = ref_in(&home, &dir, &["ref", "--json", "short=x/y"]);
        assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
        assert!(stderr(&o).contains("manifest_invalid"), "{}", stderr(&o));
        assert!(stdout(&o).is_empty(), "{}", stdout(&o));
        assert_eq!(
            std::fs::read_to_string(dir.join("envcloak.toml")).unwrap(),
            text
        );
    }
}

#[test]
fn a_hard_linked_manifest_is_left_alone() {
    let (home, _d) = unlocked_home();
    let dir = home.root().join("linked");
    std::fs::create_dir_all(&dir).unwrap();
    let text = "[env]\nA = \"a/b\"\n";
    std::fs::write(dir.join("envcloak.toml"), text).unwrap();
    std::fs::hard_link(dir.join("envcloak.toml"), dir.join("other-link.toml")).unwrap();
    let o = ref_in(&home, &dir, &["ref", "C=d/e"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("hard link"), "{}", stderr(&o));
    for name in ["envcloak.toml", "other-link.toml"] {
        assert_eq!(std::fs::read_to_string(dir.join(name)).unwrap(), text);
    }
}

#[test]
fn a_key_shaped_previous_reference_is_hidden_and_paths_are_whole() {
    let (home, _d) = unlocked_home();
    let token = Canary::new("HEX_REFERENCE", hex(40));
    let cs = [token.clone()];
    // A project under a directory named like a hash, as a git worktree or
    // a CI checkout is.
    let dir = home.root().join(hex(28)).join("proj");
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = dir.join("envcloak.toml");
    let path = std::fs::canonicalize(&dir)
        .unwrap()
        .join("envcloak.toml")
        .to_str()
        .unwrap()
        .to_owned();
    for json in [false, true] {
        std::fs::write(&manifest, format!("[env]\nX = \"{}\"\n", token.as_str())).unwrap();
        let mut args = vec!["ref", "X=openai/acme"];
        if json {
            args.push("--json");
        }
        let o = ref_in(&home, &dir, &args);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_no_canary(&o.stdout, &cs);
        assert_no_canary(&o.stderr, &cs);
        let out = stdout(&o);
        if json {
            let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
            assert_eq!(v["change"], "replaced");
            assert_eq!(v["previous"], HIDDEN);
            assert_eq!(v["manifest"], path.as_str());
        } else {
            assert!(
                out.starts_with(&format!(
                    "Set X = openai/acme in [env] in {path} (it was {HIDDEN}).\n"
                )),
                "{out}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(&manifest).unwrap(),
            "[env]\nX = \"openai/acme\"\n"
        );
    }
}
