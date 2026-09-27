//! `scripts/check-unsafe.sh` against fixture workspaces: it accepts a clean
//! tree and fails on each way of escaping the unsafe-code or secret-exposure
//! boundary. Lint names are assembled at runtime so this file does not trip
//! the script itself when it scans the real workspace.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use envcloak_testkit::TestHome;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn unsafe_lint() -> String {
    ["unsafe", "_code"].concat()
}

fn exposure_lint() -> String {
    ["clippy::disallowed", "_methods"].concat()
}

fn warnings_lint() -> String {
    ["warn", "ings"].concat()
}

/// The clean fixture's root manifest, followed by `extra`.
fn root_manifest(extra: &str) -> String {
    format!(
        "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.lints.rust]\n{} = \"deny\"\n{extra}",
        unsafe_lint()
    )
}

fn run(root: &Path) -> Output {
    Command::new("bash")
        .arg(repo_root().join("scripts/check-unsafe.sh"))
        .arg(root)
        .output()
        .unwrap()
}

fn write(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

const MEMBER: &str = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[lints]\nworkspace = true\n";

/// A minimal workspace that passes every check.
fn clean_tree() -> TestHome {
    let t = TestHome::new();
    let r = t.home();
    let uc = unsafe_lint();
    write(&r, "Cargo.toml", &root_manifest(""));
    write(
        &r,
        "clippy.toml",
        "disallowed-methods = [\n  { path = \"secrecy::ExposeSecret::expose_secret\" },\n  { path = \"secrecy::ExposeSecretMut::expose_secret_mut\" },\n]\n",
    );
    write(
        &r,
        "security/expose-allowlist.txt",
        "# comment\n\ncrates/envcloak-core/src/secret.rs  # the secret types\n",
    );
    write(&r, "crates/envcloak-sys/Cargo.toml", MEMBER);
    write(
        &r,
        "crates/envcloak-sys/src/lib.rs",
        &format!("#![allow({uc})]\n"),
    );
    write(
        &r,
        "crates/envcloak-sys/tests/t.rs",
        &format!("#![allow({uc})]\n"),
    );
    write(&r, "crates/envcloak-core/Cargo.toml", MEMBER);
    write(
        &r,
        "crates/envcloak-core/src/lib.rs",
        &format!("#![deny({uc})]\n#![warn(clippy::all)]\npub mod secret;\n"),
    );
    write(
        &r,
        "crates/envcloak-core/src/secret.rs",
        &format!("#[allow({})]\npub fn open() {{}}\n", exposure_lint()),
    );
    t
}

fn assert_passes(t: &TestHome) {
    let out = run(&t.home());
    assert!(
        out.status.success(),
        "expected a pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn assert_fails(t: &TestHome, expect_in_message: &str) {
    let out = run(&t.home());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "expected a failure mentioning {expect_in_message}"
    );
    assert!(stderr.contains(expect_in_message), "{stderr}");
}

#[test]
fn the_real_workspace_passes() {
    let out = run(&repo_root());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_clean_fixture_passes() {
    assert_passes(&clean_tree());
}

#[test]
fn allow_unsafe_code_outside_sys_fails() {
    let uc = unsafe_lint();
    for (rel, text) in [
        (
            "crates/envcloak-core/src/lib.rs",
            format!("#![allow({uc})]\n"),
        ),
        (
            "crates/envcloak-core/src/a.rs",
            format!("#[expect({uc})]\nfn f() {{}}\n"),
        ),
        (
            "crates/envcloak-core/src/b.rs",
            format!("#![allow(\n    clippy::too_many_lines,\n    {uc},\n)]\n"),
        ),
        (
            "crates/envcloak-core/tests/c.rs",
            format!("#![cfg_attr(test, allow({uc}))]\n"),
        ),
        ("tools/build.rs", format!("#![warn({uc})]\n")),
    ] {
        let t = clean_tree();
        write(&t.home(), rel, &text);
        assert_fails(&t, rel);
    }
}

#[test]
fn a_crate_that_does_not_inherit_workspace_lints_fails() {
    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/Cargo.toml",
        "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
    );
    assert_fails(&t, "crates/envcloak-core/Cargo.toml");

    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/Cargo.toml",
        &format!(
            "[package]\nname = \"x\"\n\n[lints.rust]\n{} = \"allow\"\n",
            unsafe_lint()
        ),
    );
    assert_fails(&t, "crates/envcloak-core/Cargo.toml");
}

#[test]
fn a_relaxed_workspace_lint_fails() {
    let t = clean_tree();
    write(
        &t.home(),
        "Cargo.toml",
        &format!(
            "[workspace]\n\n[workspace.lints.rust]\n{} = \"allow\"\n",
            unsafe_lint()
        ),
    );
    assert_fails(&t, "Cargo.toml");
}

#[test]
fn exposure_allowed_outside_the_allowlist_fails() {
    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/src/leaky.rs",
        &format!("#[allow({})]\nfn f() {{}}\n", exposure_lint()),
    );
    assert_fails(&t, "crates/envcloak-core/src/leaky.rs");

    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/src/broad.rs",
        &format!("#![allow({}{})]\n", "clippy::", "style"),
    );
    assert_fails(&t, "crates/envcloak-core/src/broad.rs");
}

#[test]
fn stale_allowlist_entries_fail() {
    let t = clean_tree();
    write(
        &t.home(),
        "security/expose-allowlist.txt",
        "crates/envcloak-core/src/secret.rs\ncrates/gone/src/lib.rs # removed\n",
    );
    assert_fails(&t, "crates/gone/src/lib.rs");
}

#[test]
fn weakened_clippy_configuration_fails() {
    let t = clean_tree();
    write(&t.home(), "clippy.toml", "allow-unwrap-in-tests = true\n");
    assert_fails(&t, "clippy.toml");

    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/clippy.toml",
        "disallowed-methods = []\n",
    );
    assert_fails(&t, "crates/envcloak-core/clippy.toml");
}

#[test]
fn in_a_git_checkout_ignored_files_are_skipped_and_untracked_ones_checked() {
    let t = clean_tree();
    let r = t.home();
    let git = |args: &[&str]| {
        let ok = Command::new("git")
            .arg("-C")
            .arg(&r)
            .args(args)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git {args:?}");
    };
    git(&["init", "-q"]);
    write(&r, ".gitignore", "scratch/\n");
    let violation = format!("#![allow({})]\n", unsafe_lint());
    write(&r, "scratch/copy/src/lib.rs", &violation);
    assert_passes(&t);

    // Not ignored and not yet added: still checked.
    write(&r, "crates/envcloak-core/src/new.rs", &violation);
    assert_fails(&t, "crates/envcloak-core/src/new.rs");
}

#[test]
fn allowing_warnings_anywhere_fails() {
    let w = warnings_lint();
    for (rel, text) in [
        (
            "crates/envcloak-core/src/leak.rs",
            format!("#![allow({w})]\n"),
        ),
        (
            "crates/envcloak-core/src/a.rs",
            format!("#[expect({w}, reason = \"noise\")]\nfn f() {{}}\n"),
        ),
        (
            "crates/envcloak-core/tests/b.rs",
            format!("#![cfg_attr(test, allow(\n    dead_code,\n    {w}\n))]\n"),
        ),
        // Not even envcloak-sys may do it.
        ("crates/envcloak-sys/src/c.rs", format!("#![allow({w})]\n")),
    ] {
        let t = clean_tree();
        write(&t.home(), rel, &text);
        assert_fails(&t, rel);
    }

    // Warning about warnings, or naming a variable after them, is fine.
    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/src/fine.rs",
        &format!("#![deny({w})]\nfn f() {{\n    let {w} = 1;\n    let _ = {w};\n}}\n"),
    );
    assert_passes(&t);
}

#[test]
fn relaxed_workspace_lint_tables_fail() {
    let w = warnings_lint();
    for extra in [
        "\n[workspace.lints.clippy]\ndisallowed_methods = \"allow\"\n".to_owned(),
        "\n[workspace.lints.clippy]\ndisallowed-methods = { level = \"allow\" }\n".to_owned(),
        "\n[workspace.lints.clippy]\nstyle = { level = \"allow\", priority = 1 }\n".to_owned(),
        "\n[workspace.lints.clippy]\nall = 'allow'\n".to_owned(),
        format!("{w} = \"allow\"\n"),
        "\n[workspace.lints.clippy.style]\nlevel = \"allow\"\n".to_owned(),
        "\n[workspace.lints]\nclippy = { all = \"allow\" }\n".to_owned(),
    ] {
        let t = clean_tree();
        write(&t.home(), "Cargo.toml", &root_manifest(&extra));
        assert_fails(&t, "Cargo.toml");
    }

    let t = clean_tree();
    let r = t.home();
    let text = root_manifest("").replace(
        "[workspace]\n",
        "[workspace]\nlints.clippy.all = \"allow\"\n",
    );
    write(&r, "Cargo.toml", &text);
    assert_fails(&t, "Cargo.toml");

    // Raising levels is fine.
    let t = clean_tree();
    write(
        &t.home(),
        "Cargo.toml",
        &root_manifest(&format!(
            "{w} = \"warn\"\n\n[workspace.lints.clippy]\nall = {{ level = \"warn\", priority = -1 }}\ndisallowed_methods = \"deny\"\n"
        )),
    );
    assert_passes(&t);
}

#[test]
fn comments_and_strings_neither_satisfy_nor_trip_the_checks() {
    let uc = unsafe_lint();
    for text in [
        // A deny in a trailing comment does not excuse the allow.
        format!("#![allow({uc})] // the workspace sets deny({uc})\n"),
        format!("/* deny({uc}) */ #![allow({uc})]\n"),
        format!("#![allow({uc})] const S: &str = \"deny({uc})\";\n"),
        // A deny and an allow on one line.
        format!("#![deny({uc})] #![allow({uc})]\n"),
        // A lint name that reaches an attribute some other way.
        format!("macro_rules! m {{ ($l:ident) => {{ #[allow($l)] fn f() {{}} }} }}\nm!({uc});\n"),
    ] {
        let t = clean_tree();
        write(&t.home(), "crates/envcloak-core/src/x.rs", &text);
        assert_fails(&t, "crates/envcloak-core/src/x.rs");
    }

    let w = warnings_lint();
    let dm = exposure_lint();
    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/src/y.rs",
        &format!(
            "#![deny({uc})] // allow({uc}) would fail here\n\
             // #![allow({uc})]\n\
             /* #![allow({w})] /* nested allow({dm}) */ allow(clippy::all) */\n\
             /// Doc text: allow(clippy::style)\n\
             const A: &str = \"#![allow({uc})]\";\n\
             const B: &str = r#\"allow({w}) \"quoted\" allow({dm})\"#;\n\
             const C: &[u8] = b\"allow({uc})\\\"\";\n\
             const D: char = '\"';\n\
             const E: u8 = b'\\'';\n\
             fn f<'a>(x: &'a str) -> &'a str {{\n    'outer: loop {{\n        break 'outer;\n    }}\n    let _ = \"allow(\\\"{uc}\\\")\";\n    x\n}}\n"
        ),
    );
    assert_passes(&t);
}

#[test]
fn a_file_the_check_cannot_read_fails() {
    for text in [
        "const S: &str = \"unterminated;\n",
        "/* open /* nested */\n",
    ] {
        let t = clean_tree();
        write(&t.home(), "crates/envcloak-core/src/z.rs", text);
        assert_fails(&t, "crates/envcloak-core/src/z.rs");
    }
}

#[test]
fn cargo_config_rustflags_fail() {
    let t = clean_tree();
    write(
        &t.home(),
        ".cargo/config.toml",
        &format!("[build]\nrustflags = [\"-A\", \"{}\"]\n", warnings_lint()),
    );
    assert_fails(&t, ".cargo/config.toml");
}

#[test]
fn every_package_in_the_tree_inherits_workspace_lints() {
    let t = clean_tree();
    write(
        &t.home(),
        "security/lint-canary/Cargo.toml",
        "[package]\nname = \"c\"\nversion = \"0.1.0\"\n",
    );
    assert_fails(&t, "security/lint-canary/Cargo.toml");

    let t = clean_tree();
    write(&t.home(), "security/lint-canary/Cargo.toml", MEMBER);
    assert_passes(&t);
}
