//! `scripts/check-sources.sh` against fixture workspaces that cargo really
//! compiles: every file rustc reads for a workspace crate must be a Rust
//! file `scripts/check-unsafe.sh` scans, however a macro spells the
//! `#[path]` or `include!` that pulls it in, and every proc-macro crate
//! compiled for the workspace must be on the reviewed list.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use envcloak_testkit::TestHome;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn write(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// Cargo in `dir`, with this process's toolchain but no RUSTFLAGS, so the
/// fixtures' deliberately odd code builds wherever the suite runs.
fn cargo(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.current_dir(dir)
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS");
    cmd
}

/// A workspace at `<home>/ws` with one library crate, `crates/core`, whose
/// `src/lib.rs` is `lib`. `crates/core/src/opener.txt` holds the kind of
/// code the checks exist to keep out: an allow of the expose lint in a file
/// check-unsafe.sh never reads.
fn fixture(lib: &str) -> (TestHome, PathBuf) {
    let t = TestHome::new();
    let ws = t.home().join("ws");
    write(
        &ws,
        "Cargo.toml",
        "[workspace]\nresolver = \"3\"\nmembers = [\"crates/*\"]\n",
    );
    write(
        &ws,
        "crates/core/Cargo.toml",
        "[package]\nname = \"core-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    );
    write(&ws, "crates/core/src/lib.rs", lib);
    write(
        &ws,
        "crates/core/src/opener.txt",
        "#[allow(clippy::disallowed_methods)]\npub fn open() {}\n",
    );
    write(
        &ws,
        "security/proc-macro-allowlist.txt",
        "# reviewed proc-macro crates\n",
    );
    lockfile(&ws);
    (t, ws)
}

fn lockfile(ws: &Path) {
    let out = cargo(ws)
        .args(["generate-lockfile", "--offline"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
}

fn run(ws: &Path) -> Output {
    Command::new("bash")
        .arg(repo_root().join("scripts/check-sources.sh"))
        .arg(ws)
        .env("CARGO", env!("CARGO"))
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env("CARGO_TARGET_DIR", ws.join("target"))
        .output()
        .unwrap()
}

fn assert_passes(ws: &Path) {
    let out = run(ws);
    assert!(
        out.status.success(),
        "expected a pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn assert_fails(ws: &Path, expect_in_message: &str) {
    let out = run(ws);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "expected a failure mentioning {expect_in_message}"
    );
    assert!(stderr.contains(expect_in_message), "{stderr}");
}

const OPENER: &str =
    "compiled crates/core/src/opener.txt, which scripts/check-unsafe.sh does not read";

#[test]
fn a_clean_fixture_passes() {
    let (_t, ws) = fixture("pub mod inner {\n    pub fn f() {}\n}\n");
    assert_passes(&ws);
}

/// The reviewer's bypasses of check-unsafe.sh, and a spelling with no `=`
/// at all, which no text check can tell from an ordinary macro call.
#[test]
fn a_macro_built_path_attribute_fails() {
    for lib in [
        "macro_rules! hidden { ($a:meta) => { #[$a] pub mod opener; }; }\nhidden! { path = \"opener.txt\" }\n",
        "macro_rules! hidden { (mod $a:meta) => { #[$a] pub mod opener; }; }\nhidden!(mod path = \"opener.txt\");\n",
        "macro_rules! hidden { ($k:ident $v:literal) => { #[$k = $v] pub mod opener; }; }\nhidden!(path \"opener.txt\");\n",
    ] {
        let (_t, ws) = fixture(lib);
        assert_fails(&ws, OPENER);
    }
}

#[test]
fn a_macro_built_include_fails() {
    let (_t, ws) = fixture(
        "macro_rules! pull { ($m:ident) => { pub mod opener { $m!(\"opener.txt\"); } }; }\npull!(include);\n",
    );
    assert_fails(&ws, OPENER);
}

/// Code that only a release build compiles is checked in the release run.
#[test]
fn a_release_only_module_fails() {
    let (_t, ws) = fixture(
        "macro_rules! hidden { ($k:ident $v:literal) => { #[$k = $v] pub mod opener; }; }\n#[cfg(not(debug_assertions))]\nhidden!(path \"opener.txt\");\n",
    );
    assert_fails(
        &ws,
        "release profile, shipped binaries): compiled crates/core/src/opener.txt",
    );
}

/// A `.rs` file that git ignores is not scanned, so compiling it fails too.
#[test]
fn an_ignored_rust_file_fails() {
    let (_t, ws) = fixture(
        "macro_rules! hidden { ($k:ident $v:literal) => { #[$k = $v] pub mod opener; }; }\nhidden!(path \"../../../scratch/opener.rs\");\n",
    );
    write(&ws, "scratch/opener.rs", "pub fn open() {}\n");
    write(&ws, ".gitignore", "target/\nscratch/\n");
    let ok = Command::new("git")
        .arg("-C")
        .arg(&ws)
        .args(["init", "-q"])
        .status()
        .unwrap()
        .success();
    assert!(ok, "git init");
    assert_fails(&ws, "compiled scratch/opener.rs");

    // The same file, not ignored, is scanned and may be compiled.
    write(&ws, ".gitignore", "target/\n");
    assert_passes(&ws);
}

/// A proc-macro crate outside the workspace, used by it.
fn with_proc_macro(allowlist: &str) -> (TestHome, PathBuf) {
    let (t, ws) = fixture("pub use pm_fixture::Nothing;\n");
    let pm = t.home().join("pm");
    write(
        &pm,
        "Cargo.toml",
        "[package]\nname = \"pm-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\nproc-macro = true\n",
    );
    write(
        &pm,
        "src/lib.rs",
        "use proc_macro::TokenStream;\n\n#[proc_macro_derive(Nothing)]\npub fn nothing(_: TokenStream) -> TokenStream {\n    TokenStream::new()\n}\n",
    );
    write(
        &ws,
        "crates/core/Cargo.toml",
        "[package]\nname = \"core-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\npm-fixture = { path = \"../../../pm\" }\n",
    );
    write(&ws, "security/proc-macro-allowlist.txt", allowlist);
    lockfile(&ws);
    (t, ws)
}

#[test]
fn an_unlisted_proc_macro_crate_fails() {
    let (_t, ws) = with_proc_macro("# none yet\n");
    assert_fails(
        &ws,
        "the proc-macro crate pm-fixture is compiled for the workspace but not listed",
    );

    let (_t, ws) = with_proc_macro("pm-fixture  # derives nothing\n");
    assert_passes(&ws);
}

#[test]
fn stale_proc_macro_entries_fail() {
    let (_t, ws) = fixture("pub fn f() {}\n");
    write(
        &ws,
        "security/proc-macro-allowlist.txt",
        "gone-derive  # removed from the graph\n",
    );
    assert_fails(
        &ws,
        "gone-derive is not a proc-macro package in the dependency graph",
    );
}
