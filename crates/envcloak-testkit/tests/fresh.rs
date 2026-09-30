//! `stale_source` (group 3 verification, G3-V2) against a fixture
//! workspace that cargo really builds, shaped like this one: a daemon and
//! a CLI binary over a core library, over a system library with a test
//! feature, a test-support library the daemon's tests use (as envcloakd's
//! use envcloak-testkit), and a library neither uses. A scoped build of
//! the CLI after a change to a library the daemon uses, or to a setting
//! it is built with, leaves the daemon as it was; the check names the
//! changed file until the daemon is built again, and ignores changes the
//! daemon is not built from or with.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use envcloak_testkit::{TESTKIT_BINS, TestHome, stale_source, testkit_bin_beside};

fn write(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// Cargo in `dir`, with this process's toolchain but no RUSTFLAGS, so the
/// fixture builds wherever the suite runs.
fn cargo(ws: &Path, args: &[&str]) {
    let out = Command::new(env!("CARGO"))
        .current_dir(ws)
        .env("CARGO_TARGET_DIR", ws.join("target"))
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args(args)
        .arg("--offline")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "cargo {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn fixture() -> (TestHome, PathBuf) {
    let t = TestHome::new();
    let ws = t.home().join("ws");
    let package = |name: &str| {
        format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
    };
    write(
        &ws,
        "Cargo.toml",
        "[workspace]\nresolver = \"3\"\nmembers = [\"crates/*\"]\n\n\
         [workspace.dependencies]\nfx-core = { path = \"crates/core\" }\n",
    );
    write(
        &ws,
        "crates/sys/Cargo.toml",
        &format!("{}\n[features]\ntesting = []\n", package("fx-sys")),
    );
    write(
        &ws,
        "crates/sys/src/lib.rs",
        "#[cfg(feature = \"testing\")]\npub mod testing;\npub fn sys() -> u32 {\n    1\n}\n",
    );
    write(&ws, "crates/sys/src/testing.rs", "pub fn hook() {}\n");
    // The system library only for Unix targets, as a target table, and
    // features that change what the core library computes: turning one on
    // changes the daemon with no source file changing (Codex F-66).
    write(
        &ws,
        "crates/core/Cargo.toml",
        &format!(
            "{}\n[features]\nextra = []\nmore = []\n\n\
             [target.'cfg(unix)'.dependencies]\nfx-sys = {{ path = \"../sys\" }}\n",
            package("fx-core")
        ),
    );
    write(
        &ws,
        "crates/core/src/lib.rs",
        "#[cfg(test)]\nmod tests;\npub fn core() -> u32 {\n    \
         fx_sys::sys() + 1 + if cfg!(feature = \"extra\") { 10 } else { 0 }\n    \
         + if cfg!(feature = \"more\") { 100 } else { 0 }\n}\n",
    );
    write(&ws, "crates/core/src/tests.rs", "#[test]\nfn t() {}\n");
    // The daemon: a workspace dependency, and the test feature of the
    // system library for its tests, as envcloakd's are (and the CLI's).
    write(
        &ws,
        "crates/daemon/Cargo.toml",
        &format!(
            "{}\n[dependencies]\nfx-core.workspace = true\n\n\
             [dev-dependencies]\nfx-sys = {{ path = \"../sys\", features = [\"testing\"] }}\n\
             fx-tk = {{ path = \"../tk\" }}\n",
            package("fxd")
        ),
    );
    write(
        &ws,
        "crates/daemon/src/main.rs",
        "#[cfg(test)]\nmod tests;\nfn main() {\n    println!(\"{}\", fx_core::core());\n}\n",
    );
    write(&ws, "crates/daemon/src/tests.rs", "#[test]\nfn t() {}\n");
    write(
        &ws,
        "crates/cli/Cargo.toml",
        &format!(
            "{}\n[dependencies]\nfx-core = {{ path = \"../core\" }}\n\n\
             [dev-dependencies]\nfx-sys = {{ path = \"../sys\", features = [\"testing\"] }}\n",
            package("fx")
        ),
    );
    write(
        &ws,
        "crates/cli/src/main.rs",
        "fn main() {\n    println!(\"{}\", fx_core::core());\n}\n",
    );
    // Integration tests, which are what make `cargo test` build a
    // package's binaries.
    for (dir, bin) in [("daemon", "fxd"), ("cli", "fx")] {
        write(
            &ws,
            &format!("crates/{dir}/tests/run.rs"),
            &format!("#[test]\nfn runs() {{\n    let _ = env!(\"CARGO_BIN_EXE_{bin}\");\n}}\n"),
        );
    }
    // The test-support library: a dev-dependency of the daemon, which
    // links nothing of it into the binary but builds it with its features.
    write(
        &ws,
        "crates/tk/Cargo.toml",
        &format!(
            "{}\n[dependencies]\nfx-core = {{ path = \"../core\" }}\n\
             fx-sys = {{ path = \"../sys\", features = [\"testing\"] }}\n",
            package("fx-tk")
        ),
    );
    write(&ws, "crates/tk/src/lib.rs", "pub fn tk() {}\n");
    write(&ws, "crates/other/Cargo.toml", &package("fx-other"));
    write(&ws, "crates/other/src/lib.rs", "pub fn other() {}\n");
    (t, ws)
}

/// Changes `rel` so that its modification time is after `bin`'s: now, or
/// just after the binary's when the clock has not moved on since it was
/// linked (file times can be coarser than the clock).
fn edit(ws: &Path, rel: &str, bin: &Path) {
    edit_with(ws, rel, "// changed\n", bin);
}

/// [`edit`], appending `more`.
fn edit_with(ws: &Path, rel: &str, more: &str, bin: &Path) {
    let path = ws.join(rel);
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str(more);
    replace(ws, rel, &text, bin);
}

/// Writes `text` to `rel`, its modification time after `bin`'s, as
/// [`edit`] does.
fn replace(ws: &Path, rel: &str, text: &str, bin: &Path) {
    let path = ws.join(rel);
    std::fs::write(&path, text).unwrap();
    touch(ws, rel, bin);
}

/// Gives `rel` a modification time after `bin`'s, its bytes unchanged.
fn touch(ws: &Path, rel: &str, bin: &Path) {
    let path = ws.join(rel);
    let after = std::fs::metadata(bin).unwrap().modified().unwrap() + Duration::from_millis(10);
    let at = SystemTime::now().max(after);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(at)
        .unwrap();
}

#[test]
fn a_binary_older_than_a_source_it_is_built_from_is_named() {
    let (_t, ws) = fixture();
    let fxd = ws.join("target/debug/fxd");
    let fx = ws.join("target/debug/fx");
    let stale = |bin: &Path, package: &str| {
        stale_source(bin, package, &ws)
            .unwrap()
            .map(|p| p.strip_prefix(&ws).unwrap().to_owned())
    };
    let named = |rel: &str| Some(PathBuf::from(rel));

    // Everything built, the tests' way.
    cargo(&ws, &["test", "--workspace", "--no-run"]);
    assert_eq!(stale(&fxd, "fxd"), None);
    assert_eq!(stale(&fx, "fx"), None);

    // What the daemon is not built from: a library it does not use, and
    // files only the unit tests of the core library and of the daemon
    // itself compile.
    for rel in [
        "crates/other/src/lib.rs",
        "crates/core/src/tests.rs",
        "crates/daemon/src/tests.rs",
    ] {
        edit(&ws, rel, &fxd);
        cargo(&ws, &["test", "-p", "fx", "--no-run"]);
        assert_eq!(stale(&fxd, "fxd"), None, "{rel}");
    }

    // What it is built from: the core library, the system library under
    // it (a target table), the system library's test feature, which the
    // daemon's tests compile, and the daemon's own source. A scoped build
    // of the CLI leaves the daemon as it was; a build with -p fxd makes it
    // fresh again.
    for rel in [
        "crates/core/src/lib.rs",
        "crates/sys/src/lib.rs",
        "crates/sys/src/testing.rs",
        "crates/daemon/src/main.rs",
    ] {
        edit(&ws, rel, &fxd);
        assert_eq!(stale(&fxd, "fxd"), named(rel), "{rel}");
        cargo(&ws, &["test", "-p", "fx", "--no-run"]);
        assert_eq!(
            stale(&fxd, "fxd"),
            named(rel),
            "{rel}, after a scoped build"
        );
        cargo(&ws, &["test", "-p", "fxd", "--no-run"]);
        assert_eq!(stale(&fxd, "fxd"), None, "{rel}, rebuilt");
    }
    assert_eq!(stale(&fx, "fx"), None);

    // Codex F-66: what it is built with. The daemon's manifest turns on
    // the core library's feature, no Rust file changed: the daemon cargo
    // built before prints what it did, and a scoped build of the CLI
    // leaves it so; the check names the manifest until the daemon is
    // built again, which then prints what the feature makes it print.
    let runs = |bin: &Path| {
        let out = Command::new(bin).output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    assert_eq!(runs(&fxd), "2\n");
    let daemon = "crates/daemon/Cargo.toml";
    let text = std::fs::read_to_string(ws.join(daemon)).unwrap();
    let on = text.replace(
        "fx-core.workspace = true",
        "fx-core = { workspace = true, features = [\"extra\"] }",
    );
    assert_ne!(on, text);
    replace(&ws, daemon, &on, &fxd);
    assert_eq!(stale(&fxd, "fxd"), named(daemon));
    cargo(&ws, &["test", "-p", "fx", "--no-run"]);
    assert_eq!(stale(&fxd, "fxd"), named(daemon), "after a scoped build");
    assert_eq!(runs(&fxd), "2\n", "the old build, which a test would run");
    cargo(&ws, &["test", "-p", "fxd", "--no-run"]);
    assert_eq!(stale(&fxd, "fxd"), None, "rebuilt");
    assert_eq!(runs(&fxd), "12\n", "rebuilt with the feature");
    assert_eq!(stale(&fx, "fx"), None);

    // The test-support library, a dev-dependency, turns on another
    // feature of the core library: the daemon's tests' build unifies it
    // into the daemon, which links nothing of that library.
    let tk = "crates/tk/Cargo.toml";
    let text = std::fs::read_to_string(ws.join(tk)).unwrap();
    let on = text.replace(
        "fx-core = { path = \"../core\" }",
        "fx-core = { path = \"../core\", features = [\"more\"] }",
    );
    assert_ne!(on, text);
    replace(&ws, tk, &on, &fxd);
    assert_eq!(stale(&fxd, "fxd"), named(tk));
    cargo(&ws, &["test", "-p", "fx", "--no-run"]);
    assert_eq!(stale(&fxd, "fxd"), named(tk), "after a scoped build");
    assert_eq!(runs(&fxd), "12\n", "the old build");
    cargo(&ws, &["test", "-p", "fxd", "--no-run"]);
    assert_eq!(stale(&fxd, "fxd"), None, "rebuilt");
    assert_eq!(runs(&fxd), "112\n", "rebuilt with the feature");

    // The other settings it is built with: a library's manifest it links
    // (a feature declared) and the workspace's (a profile setting); each
    // is named until the daemon is built again.
    for (rel, more) in [
        ("crates/sys/Cargo.toml", "more = []\n"),
        ("Cargo.toml", "\n[profile.dev]\noverflow-checks = false\n"),
    ] {
        edit_with(&ws, rel, more, &fxd);
        assert_eq!(stale(&fxd, "fxd"), named(rel), "{rel}");
        cargo(&ws, &["test", "-p", "fx", "--no-run"]);
        assert_eq!(
            stale(&fxd, "fxd"),
            named(rel),
            "{rel}, after a scoped build"
        );
        cargo(&ws, &["test", "-p", "fxd", "--no-run"]);
        assert_eq!(stale(&fxd, "fxd"), None, "{rel}, rebuilt");
    }

    // What it is not built with: the CLI's and the unused library's
    // manifests, and the test-support library's source.
    for rel in [
        "crates/cli/Cargo.toml",
        "crates/other/Cargo.toml",
        "crates/tk/src/lib.rs",
    ] {
        let more = if rel.ends_with(".rs") {
            "// changed\n"
        } else {
            "# changed\n"
        };
        edit_with(&ws, rel, more, &fxd);
        cargo(&ws, &["test", "-p", "fx", "--no-run"]);
        assert_eq!(stale(&fxd, "fxd"), None, "{rel}");
    }

    // The cost of refusing (review R-2): a setting changed in a way cargo
    // rebuilds nothing for, here Cargo.lock with its bytes unchanged,
    // leaves the daemon older than it, so it is still named after the
    // daemon's own build, until `cargo clean -p fxd` makes the next build
    // link it again, as the refusal says.
    touch(&ws, "Cargo.lock", &fxd);
    cargo(&ws, &["test", "-p", "fxd", "--no-run"]);
    assert_eq!(stale(&fxd, "fxd"), named("Cargo.lock"), "nothing rebuilt");
    cargo(&ws, &["clean", "-p", "fxd"]);
    cargo(&ws, &["test", "-p", "fxd", "--no-run"]);
    assert_eq!(stale(&fxd, "fxd"), None, "cleaned and rebuilt");

    // Nothing says a binary is fresh when its build cannot be found: a
    // copy outside the target directory, one cargo did not build there, a
    // package that is not a member, or a library build that is gone.
    let elsewhere = ws.join("elsewhere");
    std::fs::create_dir_all(elsewhere.join("deps")).unwrap();
    std::fs::copy(&fxd, elsewhere.join("fxd")).unwrap();
    assert!(stale_source(&elsewhere.join("fxd"), "fxd", &ws).is_err());
    let copy = ws.join("target/debug/fxd-copy");
    std::fs::copy(&fxd, &copy).unwrap();
    assert!(stale_source(&copy, "fxd", &ws).is_err());
    assert!(stale_source(&fxd, "fx-none", &ws).is_err());
    let deps = ws.join("target/debug/deps");
    for e in std::fs::read_dir(&deps).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_str().unwrap().to_owned();
        if name.starts_with("libfx_sys-") && name.ends_with(".rlib") {
            std::fs::remove_file(p).unwrap();
        }
    }
    let err = stale_source(&fxd, "fxd", &ws).unwrap_err();
    assert!(err.contains("fx_sys"), "{err}");
}

/// Review R-1: the testkit's own programs ran from the target directory
/// unchecked, so a scoped run after a change to envcloak-sys (which
/// `ec-probe` links) ran the old `ec-probe`. `testkit_bin` takes a program
/// as new as its sources and refuses one older than them, naming the
/// command that builds it. The program here is a copy of the real
/// `ec-probe` in a profile directory of its own whose `deps/` is the real
/// one, so the real build's dep-info is read and the real program is left
/// as it is.
#[test]
fn testkit_bin_refuses_a_program_older_than_its_sources() {
    let real = Path::new(env!("CARGO_BIN_EXE_ec-probe"));
    let t = TestHome::new();
    let profile = t.home().join("profile");
    std::fs::create_dir_all(&profile).unwrap();
    std::os::unix::fs::symlink(real.parent().unwrap().join("deps"), profile.join("deps")).unwrap();
    // The test binary asking: only its directory counts.
    let exe = profile.join("deps").join("a-test");
    let copy = profile.join("ec-probe");
    std::fs::copy(real, &copy).unwrap();
    let modified = |at: SystemTime| {
        std::fs::File::options()
            .write(true)
            .open(&copy)
            .unwrap()
            .set_modified(at)
            .unwrap();
    };

    modified(SystemTime::now());
    assert_eq!(testkit_bin_beside(&exe, "ec-probe"), copy);

    modified(SystemTime::UNIX_EPOCH + Duration::from_secs(86_400));
    let refused = std::panic::catch_unwind(|| testkit_bin_beside(&exe, "ec-probe"))
        .expect_err("an ec-probe older than its sources was taken");
    let message = refused.downcast_ref::<String>().map_or("", String::as_str);
    assert!(
        message.contains("is older than") && message.contains(TESTKIT_BINS),
        "{message}"
    );
}
