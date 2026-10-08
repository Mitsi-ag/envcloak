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

/// `disallowed_methods`, as a key in a clippy lint table.
fn exposure_key() -> String {
    ["disallowed", "_methods"].concat()
}

fn exposure_lint() -> String {
    format!("clippy::{}", exposure_key())
}

fn warnings_lint() -> String {
    ["warn", "ings"].concat()
}

/// `expose_secret`, the method clippy.toml forbids.
fn expose_method() -> String {
    ["expose", "_secret"].concat()
}

/// `ExposeSecret`, its trait.
fn expose_trait() -> String {
    ["Expose", "Secret"].concat()
}

/// The clean fixture's `[workspace.lints.clippy]` body.
fn clippy_body() -> String {
    format!(
        "all = {{ level = \"warn\", priority = -1 }}\n{} = \"deny\"\n",
        exposure_key()
    )
}

/// A root manifest whose `[workspace.lints.rust]` table forbids unsafe code
/// and adds `rust`, whose clippy table holds `clippy_lints`, followed by
/// `tail`.
fn root_manifest(rust: &str, clippy_lints: &str, tail: &str) -> String {
    format!(
        "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.lints.rust]\n{} = \"forbid\"\n{rust}\n[workspace.lints.clippy]\n{clippy_lints}\n{tail}",
        unsafe_lint()
    )
}

/// envcloak-sys's manifest, repeating those tables with unsafe code denied.
fn sys_manifest(rust: &str, clippy_lints: &str) -> String {
    format!(
        "[package]\nname = \"envcloak-sys\"\nversion = \"0.1.0\"\n\n[lints.rust]\n{} = \"deny\"\n{rust}\n[lints.clippy]\n{clippy_lints}",
        unsafe_lint()
    )
}

/// Writes a matching root and envcloak-sys manifest pair.
fn set_lints(t: &TestHome, rust: &str, clippy_lints: &str) {
    write(
        &t.home(),
        "Cargo.toml",
        &root_manifest(rust, clippy_lints, ""),
    );
    write(
        &t.home(),
        "crates/envcloak-sys/Cargo.toml",
        &sys_manifest(rust, clippy_lints),
    );
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
    set_lints(&t, "", &clippy_body());
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
        &format!(
            "#[allow({})]\npub fn open() {{}}\n\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn t() {{}}\n}}\n",
            exposure_lint()
        ),
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
fn allowlist_membership_does_not_depend_on_pipe_capacity() {
    let t = clean_tree();
    assert_passes(&t);
    // Repeated valid entries keep the same membership but exceed a pipe's
    // capacity. A reader that exits on its first match can break the writer.
    let member = "crates/envcloak-core/src/secret.rs\n";
    write(
        &t.home(),
        "security/expose-allowlist.txt",
        &member.repeat(8192),
    );
    assert_passes(&t);
    write(&t.home(), "security/expose-allowlist.txt", "# no members\n");
    assert_fails(&t, "crates/envcloak-core/src/secret.rs");
}

#[test]
fn ci_version_probe_consumes_the_producers_output() {
    let workflow = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).unwrap();
    let line = workflow
        .lines()
        .find(|s| s.contains("xcodebuild -version | "))
        .unwrap();
    let reader = line
        .split_once(" | ")
        .unwrap()
        .1
        .split_once(" || {")
        .unwrap()
        .0;
    let expected = reader.split('"').nth(1).unwrap();
    let t = TestHome::new();
    for (version, success) in [(expected, true), ("Build version fixture-mismatch", false)] {
        let mut cmd = Command::new("bash");
        t.apply(&mut cmd).env("FIXTURE_VERSION", version).args(["-c", &format!(
            r#"set -o pipefail
python3 -c 'import os,sys; sys.stdout.write(os.environ["FIXTURE_VERSION"]+"\n"); sys.stdout.flush(); sys.stdout.write("trailer\n"*131072)' | {reader}"#
        )]);
        let out = cmd.output().unwrap();
        assert_eq!(
            out.status.success(),
            success,
            "version pipeline: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty());
    }
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
fn raw_identifier_lint_names_are_read_as_rustc_reads_them() {
    let uc = unsafe_lint();
    let dm = exposure_key();
    let w = warnings_lint();
    for (text, message) in [
        (
            format!("#[allow(r#{uc})]\nfn f() {{}}\n"),
            "unsafe_code may only be relaxed",
        ),
        (
            format!("#[allow(clippy::r#{dm})]\nfn f() {{}}\n"),
            "allows disallowed_methods but is not listed",
        ),
        (
            format!("#[allow(r#clippy::r#{dm})]\nfn f() {{}}\n"),
            "allows disallowed_methods but is not listed",
        ),
        (
            format!("#[allow(r#{w})]\nfn f() {{}}\n"),
            "must not allow warnings",
        ),
        (
            "#![allow(clippy::r#style)]\n".to_owned(),
            "may not be allowed",
        ),
        (
            "#![expect(r#clippy::r#all)]\n".to_owned(),
            "may not be allowed",
        ),
        (
            format!("macro_rules! m {{ ($l:ident) => {{}} }}\nm!(r#{uc});\n"),
            "mentions unsafe_code outside a lint attribute",
        ),
    ] {
        let t = clean_tree();
        write(&t.home(), "crates/envcloak-core/src/raw.rs", &text);
        assert_fails(&t, message);
    }

    // Raw identifiers elsewhere are fine.
    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/src/fine.rs",
        "pub fn f(r#type: u8) -> u8 {\n    let r#match = r#type;\n    r#match\n}\n",
    );
    assert_passes(&t);
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

    // `workspace = true` inside a string is not a lints table (the old
    // line-based reading took it for one).
    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/Cargo.toml",
        &format!(
            "[package]\nname = \"x\"\ndescription = \"\"\"\n[lints]\nworkspace = true\n\"\"\"\n\n[lints.rust]\n{} = \"allow\"\n",
            warnings_lint()
        ),
    );
    assert_fails(
        &t,
        "crates/envcloak-core/Cargo.toml: needs [lints] workspace = true",
    );
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
    assert_fails(&t, "must set unsafe_code = \"forbid\"");

    // Deny is not enough: a source attribute can lower a deny, not a forbid.
    let t = clean_tree();
    let text = root_manifest("", &clippy_body(), "").replace("\"forbid\"", "\"deny\"");
    write(&t.home(), "Cargo.toml", &text);
    assert_fails(&t, "must set unsafe_code = \"forbid\"");
}

#[test]
fn workspace_tables_are_read_as_cargo_reads_them() {
    let uc = unsafe_lint();
    let dm = exposure_key();
    // The reviewer's bypass: the required line sits in a multi-line string,
    // and the real table has a quoted key the old line match did not know.
    let decoy = format!(
        "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.metadata.notes]\ntext = \"\"\"\n[workspace.lints.rust]\n{uc} = \"forbid\"\n\"\"\"\n\n[workspace.\"lints\".rust]\n{uc} = \"allow\"\n\n[workspace.\"lints\".clippy]\n{dm} = \"deny\"\n"
    );
    // Inline and dotted spellings of a relaxed level.
    let inline = format!(
        "[workspace]\nlints = {{ rust = {{ {uc} = \"forbid\" }}, clippy = {{ all = \"allow\", {dm} = \"deny\" }} }}\n"
    );
    let dotted = format!(
        "[workspace]\nlints.rust.{uc} = \"forbid\"\nlints.clippy.{dm} = \"deny\"\nlints.clippy.style = {{ level = \"allow\", priority = 1 }}\n"
    );
    for (text, message) in [
        (decoy, "must set unsafe_code = \"forbid\""),
        (inline, "all must stay at warn or above"),
        (dotted, "style must stay at warn or above"),
    ] {
        let t = clean_tree();
        write(&t.home(), "Cargo.toml", &text);
        assert_fails(&t, message);
    }

    // A file that is not valid TOML fails rather than being skipped.
    let t = clean_tree();
    write(
        &t.home(),
        "Cargo.toml",
        &root_manifest("", &clippy_body(), "[workspace.lints.rust]\n"),
    );
    assert_fails(&t, "Cargo.toml: cannot be read as TOML");
}

#[test]
fn relaxed_workspace_lint_tables_fail() {
    let dm = exposure_key();
    let w = warnings_lint();
    let all = "all = { level = \"warn\", priority = -1 }\n";
    for (rust, clippy_lints, message) in [
        (
            String::new(),
            format!("{all}{dm} = \"allow\"\n"),
            "must set disallowed_methods = \"deny\"",
        ),
        (
            String::new(),
            format!("{all}disallowed-methods = {{ level = \"warn\" }}\n"),
            "must set disallowed_methods = \"deny\"",
        ),
        (
            String::new(),
            all.to_owned(),
            "must set disallowed_methods = \"deny\"",
        ),
        (
            String::new(),
            format!("{all}{dm} = \"deny\"\nstyle = {{ level = \"allow\", priority = 1 }}\n"),
            "style must stay at warn or above",
        ),
        (
            String::new(),
            format!("all = 'allow'\n{dm} = \"deny\"\n"),
            "all must stay at warn or above",
        ),
        // A group applied after disallowed_methods would set its level.
        (
            String::new(),
            format!("all = {{ level = \"warn\", priority = 5 }}\n{dm} = \"deny\"\n"),
            "needs a lower priority than disallowed_methods",
        ),
        (
            String::new(),
            format!("{all}{dm} = \"deny\"\n\"clippy::style\" = \"allow\"\n"),
            "use one plain lint name per key",
        ),
        (
            String::new(),
            format!("{all}{dm} = \"deny\"\n{dm} = \"deny\"\n"),
            "cannot be read as TOML",
        ),
        (
            String::new(),
            format!("{all}{dm} = \"deny\"\ndisallowed-methods = \"deny\"\n"),
            "this lint is set twice",
        ),
        (
            format!("{w} = \"allow\"\n"),
            clippy_body(),
            "warnings must stay at warn or above",
        ),
    ] {
        let t = clean_tree();
        set_lints(&t, &rust, &clippy_lints);
        assert_fails(&t, message);
    }

    // A sub-table sets the group's level too.
    let t = clean_tree();
    write(
        &t.home(),
        "Cargo.toml",
        &root_manifest(
            "",
            &clippy_body(),
            "[workspace.lints.clippy.style]\nlevel = \"allow\"\n",
        ),
    );
    assert_fails(&t, "style must stay at warn or above");

    // Raising levels is fine.
    let t = clean_tree();
    set_lints(
        &t,
        &format!("{w} = \"warn\"\n"),
        &format!("{all}{dm} = {{ level = \"forbid\", priority = 1 }}\n"),
    );
    assert_passes(&t);
}

#[test]
fn the_sys_lint_tables_must_mirror_the_workspace() {
    let uc = unsafe_lint();
    let w = warnings_lint();
    let body = clippy_body();
    for text in [
        // Inheriting would forbid the unsafe code sys exists for; it is
        // still reported, so the tree says what it means.
        MEMBER.to_owned(),
        sys_manifest("", &format!("{body}unwrap_used = \"allow\"\n")),
        sys_manifest(&format!("{w} = \"allow\"\n"), &body),
        sys_manifest("", "all = { level = \"warn\", priority = -1 }\n"),
        sys_manifest("", &body).replace("\"deny\"\n", "\"allow\"\n"),
        format!("[package]\nname = \"envcloak-sys\"\n\n[lints.rust]\n{uc} = \"deny\"\n"),
    ] {
        let t = clean_tree();
        write(&t.home(), "crates/envcloak-sys/Cargo.toml", &text);
        assert_fails(&t, "crates/envcloak-sys/Cargo.toml: its [lints] tables");
    }
}

#[test]
fn build_scripts_proc_macros_and_outside_targets_fail() {
    let lints = "\n[lints]\nworkspace = true\n";
    for (extra_manifest, files, message) in [
        ("", vec![("build.rs", "fn main() {}\n")], "build scripts"),
        ("build = \"gen.rs\"\n", vec![], "build scripts"),
        ("\n[lib]\nproc-macro = true\n", vec![], "proc-macro crates"),
        ("\n[lib]\npath = \"src/lib.txt\"\n", vec![], "[lib] path"),
        (
            "\n[[bin]]\nname = \"b\"\npath = \"../../outside/main.rs\"\n",
            vec![],
            "[bin] path",
        ),
        (
            "\n[[test]]\nname = \"t\"\npath = \"/tmp/t.rs\"\n",
            vec![],
            "[test] path",
        ),
    ] {
        let t = clean_tree();
        let r = t.home();
        let (package, rest) = match extra_manifest.strip_prefix('\n') {
            Some(tables) => (String::new(), format!("{lints}\n{tables}")),
            None => (extra_manifest.to_owned(), lints.to_owned()),
        };
        write(
            &r,
            "crates/envcloak-core/Cargo.toml",
            &format!("[package]\nname = \"x\"\nversion = \"0.1.0\"\n{package}{rest}"),
        );
        for (name, text) in files {
            write(&r, &format!("crates/envcloak-core/{name}"), text);
        }
        assert_fails(&t, message);
    }

    // A build script switched off, and targets inside the package, are fine.
    let t = clean_tree();
    let r = t.home();
    write(
        &r,
        "crates/envcloak-core/Cargo.toml",
        "[package]\nname = \"x\"\nversion = \"0.1.0\"\nbuild = false\n\n[lints]\nworkspace = true\n\n[[test]]\nname = \"t\"\npath = \"tests/t.rs\"\n",
    );
    write(&r, "crates/envcloak-core/build.rs", "fn main() {}\n");
    assert_passes(&t);
}

#[test]
fn patches_and_rustflags_in_manifests_fail() {
    for (tail, message) in [
        (
            "[patch.crates-io]\nsecrecy = { path = \"vendor/secrecy\" }\n",
            "[patch] is not allowed",
        ),
        (
            "[replace]\n\"zeroize:1.9.0\" = { path = \"vendor/zeroize\" }\n",
            "[replace] is not allowed",
        ),
        (
            "[profile.dev]\nrustflags = [\"-A\", \"x\"]\n",
            "must not set rustflags",
        ),
    ] {
        let t = clean_tree();
        write(
            &t.home(),
            "Cargo.toml",
            &root_manifest("", &clippy_body(), tail),
        );
        assert_fails(&t, message);
    }
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

/// Review T1-1: clippy lints only the configurations CI compiles, so a call
/// under another target's cfg needs no allow and passed every check. The
/// text check refuses the names themselves outside the allowlist, in any
/// configuration.
#[test]
fn exposure_names_outside_the_allowlist_fail_in_any_configuration() {
    let m = expose_method();
    let t = expose_trait();
    let rel = "crates/envcloak-core/src/open.rs";
    let cases = [
        // A plain call under another target's cfg: no allow needed there.
        format!(
            "#[cfg(target_arch = \"x86\")]\npub fn open(s: &secrecy::SecretBox<[u8]>) -> &[u8] {{\n    s.{m}()\n}}\n"
        ),
        format!("#[cfg(target_env = \"musl\")]\nfn f(s: &S) -> u8 {{\n    s.{m}()[0]\n}}\n"),
        // Calls by path (UFCS), and the mutable form.
        format!("fn f(s: &S) -> &[u8] {{\n    secrecy::{t}::{m}(s)\n}}\n"),
        format!("fn f(s: &S) -> &[u8] {{\n    <S as {t}<[u8]>>::{m}(s)\n}}\n"),
        format!("fn f(s: &mut S) {{\n    s.{m}_mut()[0] = 1;\n}}\n"),
        // Imports, renamed or not.
        format!("use secrecy::{t};\n"),
        format!("#[cfg(windows)]\nuse secrecy::{{SecretBox, {t}Mut as Peek}};\n"),
        // A raw identifier, a call split over lines, and a function
        // reference where a lint group would be.
        format!("fn f(s: &S) -> &[u8] {{\n    s.r#{m}()\n}}\n"),
        format!("fn f(s: &S) -> &[u8] {{\n    s\n        .{m}\n        ()\n}}\n"),
        format!("fn f() {{\n    allow({t}::{m});\n}}\n"),
    ];
    // Every case is tried, and every one that got through is named.
    let missed: Vec<&String> = cases
        .iter()
        .filter(|text| {
            let tree = clean_tree();
            write(&tree.home(), rel, text);
            let out = run(&tree.home());
            let stderr = String::from_utf8_lossy(&out.stderr);
            out.status.success()
                || !stderr.contains(&format!("{rel}:"))
                || !stderr.contains("names expose_secret or ExposeSecret but is not listed")
        })
        .collect();
    assert!(
        missed.is_empty(),
        "{} of {} cases were not refused:\n{missed:#?}",
        missed.len(),
        cases.len()
    );

    // In a listed file, in comments and strings, and as part of longer
    // names, they are fine; so is the lint canary, which opens secrets on
    // purpose, and only it.
    let tree = clean_tree();
    let r = tree.home();
    write(
        &r,
        "crates/envcloak-core/src/secret.rs",
        &format!(
            "#[allow({})]\npub fn open(s: &S) -> &[u8] {{\n    secrecy::{t}::{m}(s)\n}}\n",
            exposure_lint()
        ),
    );
    write(
        &r,
        "crates/envcloak-core/src/fine.rs",
        &format!(
            "// s.{m}() is allowed only in listed files.\n\
             /// Never call `{t}::{m}` here.\n\
             const A: &str = \"s.{m}()\";\n\
             fn {m}s() {{}}\n\
             fn my_{m}_helper() {{}}\n\
             struct {t}ly;\n\
             struct Not{t};\n"
        ),
    );
    let canary = format!(
        "#![cfg(envcloak_lint_canary)]\nuse secrecy::{t};\npub fn f(s: &S) -> &[u8] {{\n    s.{m}()\n}}\n"
    );
    write(&r, "security/lint-canary/src/lib.rs", &canary);
    assert_passes(&tree);
    write(&r, "security/unsafe-canary/src/lib.rs", &canary);
    assert_fails(
        &tree,
        "security/unsafe-canary/src/lib.rs:2: names expose_secret",
    );
}

/// The lint canary's exemption holds only while it is compiled out of
/// every build but check-expose-lint.sh's: its lib.rs must start with the
/// crate-level cfg, and no other file of it is exempt (verification of
/// review T1-1).
#[test]
fn the_lint_canary_is_exempt_only_while_compiled_out() {
    let m = expose_method();
    let t = expose_trait();
    let rel = "security/lint-canary/src/lib.rs";
    let body = format!("use secrecy::{t};\npub fn f(s: &S) -> &[u8] {{\n    s.{m}()\n}}\n");
    for text in [
        format!("#![cfg(envcloak_lint_canary)]\n{body}"),
        format!("//! Docs first.\n/* a comment */\n#! [ cfg( envcloak_lint_canary ) ]\n{body}"),
    ] {
        let tree = clean_tree();
        write(&tree.home(), rel, &text);
        assert_passes(&tree);
    }
    let cases = [
        // No cfg; one after another attribute; a widened or misspelled
        // cfg; an outer attribute; the cfg only in a comment or a string.
        body.clone(),
        format!(
            "#![cfg_attr(target_arch = \"x86\", cfg(all()))]\n#![cfg(envcloak_lint_canary)]\n{body}"
        ),
        format!("#![cfg(any(envcloak_lint_canary, target_env = \"musl\"))]\n{body}"),
        format!("#![cfg(envcloak_lint_canary_x)]\n{body}"),
        format!("#[cfg(envcloak_lint_canary)]\n{body}"),
        format!("// #![cfg(envcloak_lint_canary)]\n{body}"),
        format!("const A: &str = \"#![cfg(envcloak_lint_canary)]\";\n{body}"),
    ];
    let missed: Vec<&String> = cases
        .iter()
        .filter(|text| {
            let tree = clean_tree();
            write(&tree.home(), rel, text);
            let out = run(&tree.home());
            let stderr = String::from_utf8_lossy(&out.stderr);
            out.status.success()
                || !stderr.contains(&format!(
                    "{rel}:1: must start with #![cfg(envcloak_lint_canary)]"
                ))
        })
        .collect();
    assert!(
        missed.is_empty(),
        "{} of {} cases were not refused:\n{missed:#?}",
        missed.len(),
        cases.len()
    );

    // Any other file of the canary crate is checked like every file.
    for other in [
        "security/lint-canary/src/more.rs",
        "security/lint-canary/tests/t.rs",
        "security/lint-canary/src/bin/b.rs",
    ] {
        let tree = clean_tree();
        write(
            &tree.home(),
            rel,
            &format!("#![cfg(envcloak_lint_canary)]\n{body}"),
        );
        write(&tree.home(), other, &body);
        assert_fails(&tree, &format!("{other}:1: names expose_secret"));
    }
}

/// No crate may depend on a canary crate, however it names it: the
/// canaries' code is kept out of builds only by their cfgs (verification of
/// review T1-1).
#[test]
fn no_manifest_may_depend_on_a_canary() {
    let member = |deps: &str| format!("{MEMBER}\n{deps}");
    let core = "crates/envcloak-core/Cargo.toml";
    let cases = [
        (
            core,
            member(
                "[dependencies]\nenvcloak-lint-canary = { path = \"../../security/lint-canary\" }\n",
            ),
        ),
        (
            core,
            member(
                "[dependencies]\nhelper = { package = \"envcloak-lint-canary\", version = \"0.1\" }\n",
            ),
        ),
        (
            core,
            member("[dependencies]\nhelper = { path = \"../../security/lint-canary/\" }\n"),
        ),
        (
            core,
            member("[dependencies.helper]\npath = \"../../security/./unsafe-canary\"\n"),
        ),
        (
            core,
            member("[dependencies]\nenvcloak_unsafe_canary = \"0.1\"\n"),
        ),
        (
            core,
            member(
                "[dev-dependencies]\nenvcloak-lint-canary = { path = \"../../security/lint-canary\" }\n",
            ),
        ),
        (
            core,
            member(
                "[build-dependencies]\nenvcloak-unsafe-canary = { path = \"../../security/unsafe-canary\" }\n",
            ),
        ),
        (
            core,
            member(
                "[target.'cfg(target_arch = \"x86\")'.dependencies]\nhelper = { path = \"../../security/lint-canary\" }\n",
            ),
        ),
        (
            core,
            member("[dependencies]\nhelper = { workspace = true }\n"),
        ),
    ];
    let mut missed = Vec::new();
    for (i, (rel, text)) in cases.iter().enumerate() {
        let tree = clean_tree();
        write(&tree.home(), rel, text);
        if i == cases.len() - 1 {
            // Inherited: the workspace table names the canary.
            write(
                &tree.home(),
                "Cargo.toml",
                &root_manifest(
                    "",
                    &clippy_body(),
                    "[workspace.dependencies]\nhelper = { path = \"security/lint-canary\" }\n",
                ),
            );
        }
        let out = run(&tree.home());
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || !stderr.contains("no crate may depend on a canary crate") {
            missed.push(text);
        }
    }
    assert!(
        missed.is_empty(),
        "{} of {} cases were not refused:\n{missed:#?}",
        missed.len(),
        cases.len()
    );

    // Other path dependencies are fine.
    let tree = clean_tree();
    write(
        &tree.home(),
        core,
        &member(
            "[dependencies]\nhelper = { path = \"../../security/lint-canary-helper\" }\nother = { path = \"../other\" }\n",
        ),
    );
    assert_passes(&tree);
}

#[test]
fn listed_files_may_not_define_macros() {
    // A macro in a listed file would open a secret wherever it is used.
    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/src/secret.rs",
        &format!(
            "#[allow({})]\npub fn open() {{}}\n\nmacro_rules! peek {{ ($s:expr) => {{ $s }} }}\n",
            exposure_lint()
        ),
    );
    assert_fails(
        &t,
        "crates/envcloak-core/src/secret.rs:4: files listed in security/expose-allowlist.txt may not define macros",
    );

    // Elsewhere a macro is fine.
    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/src/other.rs",
        "macro_rules! twice { ($e:expr) => { $e + $e } }\n",
    );
    assert_passes(&t);
}

#[test]
fn listed_files_may_not_declare_out_of_line_modules() {
    // The allow in secret.rs would reach secret/leak.rs, which is not listed.
    let t = clean_tree();
    let r = t.home();
    write(
        &r,
        "crates/envcloak-core/src/secret.rs",
        &format!("#![allow({})]\n\nmod leak;\n", exposure_lint()),
    );
    write(&r, "crates/envcloak-core/src/secret/leak.rs", "fn f() {}\n");
    assert_fails(
        &t,
        "crates/envcloak-core/src/secret.rs:3: files listed in security/expose-allowlist.txt may not declare out-of-line modules",
    );

    // The same declaration in an unlisted file is fine.
    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/src/other.rs",
        "mod inner;\n",
    );
    assert_passes(&t);
}

#[test]
fn include_and_path_attributes_fail() {
    let i = ["incl", "ude"].concat();
    let p = ["pa", "th"].concat();
    for text in [
        format!("{i}!(\"leak.txt\");\n"),
        format!("fn f() {{\n    std::{i}!(\"/tmp/leak.txt\");\n}}\n"),
        format!("r#{i}!(\"leak.txt\");\n"),
        format!("#[{p} = \"leak.txt\"]\nmod leak;\n"),
        format!("#[cfg_attr(all(), {p} = \"leak.txt\")]\nmod leak;\n"),
        format!("#[\n    {p}\n    = \"leak.txt\"\n]\nmod leak;\n"),
        // A macro that receives the pieces from elsewhere.
        format!("macro_rules! m {{ ($m:ident) => {{ $m!(\"leak.txt\"); }} }}\nm!({i});\n"),
        format!(
            "macro_rules! m {{ ($a:meta) => {{ #[$a] mod leak; }} }}\nm!({p} = \"leak.txt\");\n"
        ),
        // The reviewer's bypasses: the argument sits after `{` or `mod`,
        // or ends in `;`. scripts/check-sources.sh catches every spelling
        // (tests/check_sources.rs); these keep the text check honest too.
        format!(
            "macro_rules! m {{ ($a:meta) => {{ #[$a] pub mod leak; }}; }}\nm! {{ {p} = \"leak.txt\" }}\n"
        ),
        format!(
            "macro_rules! m {{ (mod $a:meta) => {{ #[$a] pub mod leak; }}; }}\nm!(mod {p} = \"leak.txt\");\n"
        ),
        format!(
            "macro_rules! m {{ ($a:meta;) => {{ #[$a] pub mod leak; }}; }}\nm! {{ {p} = r#\"leak.txt\"#; }}\n"
        ),
    ] {
        let t = clean_tree();
        write(&t.home(), "crates/envcloak-core/src/inc.rs", &text);
        assert_fails(&t, "crates/envcloak-core/src/inc.rs");
    }

    // Ordinary uses of the words are fine.
    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/src/fine.rs",
        &format!(
            "// {i}!(\"in a comment\") and #[{p} = \"x\"]\n\
             const A: &str = \"{i}!(x) #[{p} = y]\";\n\
             const B: &[u8] = {i}_bytes!(\"fine.rs\");\n\
             fn f(x: u8) -> u8 {{\n    let {p} = 1;\n    let mut q = {p};\n    q = q + {p};\n    if {p} == q {{}}\n    match x {{\n        0 => 1,\n        {p} => {p},\n    }}\n}}\n\
             fn g() -> usize {{\n    let {p} = \"a\";\n    let mut other = \"b\";\n    other = {p};\n    let mut {p} = \"c\";\n    {p} = other;\n    {p}.len()\n}}\n"
        ),
    );
    assert_passes(&t);
}

#[test]
fn the_clippy_cfg_fails() {
    // Code under cfg(not(clippy)) compiles but is never linted, so it could
    // call expose_secret anywhere.
    for text in [
        "#[cfg(not(clippy))]\npub fn open() {}\n",
        "#[cfg_attr(clippy, allow(dead_code))]\nfn f() {}\n",
        "fn f() -> bool {\n    cfg!(clippy)\n}\n",
        "#[cfg(not(r#clippy))]\nfn f() {}\n",
        "#[cfg(any(test, clippy\n))]\nfn f() {}\n",
        "macro_rules! m { ($c:ident) => { #[cfg(not($c))] fn f() {} } }\nm!(clippy);\n",
    ] {
        let t = clean_tree();
        write(&t.home(), "crates/envcloak-core/src/hide.rs", text);
        assert_fails(&t, "names the clippy cfg");
    }

    // Lint paths, tool attributes and longer names are fine.
    let t = clean_tree();
    write(
        &t.home(),
        "crates/envcloak-core/src/fine.rs",
        "#![allow(clippy::unwrap_used)]\n#[cfg_attr(test, allow(clippy\n    ::too_many_lines))]\n#[clippy::msrv = \"1.85\"]\nfn f() {\n    let clippy_lints = 1;\n    let _ = clippy_lints;\n}\n",
    );
    assert_passes(&t);
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

    // Paths in a comment do not configure anything.
    let t = clean_tree();
    write(
        &t.home(),
        "clippy.toml",
        "# \"secrecy::ExposeSecret::expose_secret\"\n# \"secrecy::ExposeSecretMut::expose_secret_mut\"\ndisallowed-methods = []\n",
    );
    assert_fails(&t, "clippy.toml: disallowed-methods must list");

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
fn cargo_configuration_files_fail() {
    for (rel, text) in [
        (
            ".cargo/config.toml",
            format!("[build]\nrustflags = [\"-A\", \"{}\"]\n", warnings_lint()),
        ),
        (
            ".cargo/config.toml",
            "[build]\nrustc-workspace-wrapper = \"tools/strip-lints\"\n".to_owned(),
        ),
        (
            ".cargo/config",
            "[env]\nCLIPPY_CONF_DIR = \"/tmp\"\n".to_owned(),
        ),
        (
            "crates/envcloak-core/.cargo/config.toml",
            "[env]\nX = \"1\"\n".to_owned(),
        ),
    ] {
        let t = clean_tree();
        write(&t.home(), rel, &text);
        assert_fails(&t, rel);
    }
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

    // A nested workspace or virtual manifest is not a package of this one.
    let t = clean_tree();
    write(&t.home(), "tools/Cargo.toml", "[workspace]\nmembers = []\n");
    assert_fails(&t, "tools/Cargo.toml: must be a package of this workspace");

    let t = clean_tree();
    write(
        &t.home(),
        "tools/Cargo.toml",
        "[package]\nname = \"t\"\nversion = \"0.1.0\"\n\n[workspace]\n\n[lints]\nworkspace = true\n",
    );
    assert_fails(&t, "tools/Cargo.toml: must be a package of this workspace");

    let t = clean_tree();
    write(&t.home(), "security/lint-canary/Cargo.toml", MEMBER);
    assert_passes(&t);
}
