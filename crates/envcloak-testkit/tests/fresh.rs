//! `stale_source` (group 3 verification, G3-V2) against a fixture
//! workspace that cargo really builds, shaped like this one: a daemon and
//! a CLI binary over a core library, over a system library with a test
//! feature, and a library neither uses. A scoped build of the CLI after a
//! change to a library the daemon uses leaves the daemon as it was; the
//! check names the changed file until the daemon is built again, and
//! ignores changes the daemon is not built from.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use envcloak_testkit::{TestHome, stale_source};

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
    // The system library only for Unix targets, as a target table.
    write(
        &ws,
        "crates/core/Cargo.toml",
        &format!(
            "{}\n[target.'cfg(unix)'.dependencies]\nfx-sys = {{ path = \"../sys\" }}\n",
            package("fx-core")
        ),
    );
    write(
        &ws,
        "crates/core/src/lib.rs",
        "#[cfg(test)]\nmod tests;\npub fn core() -> u32 {\n    fx_sys::sys() + 1\n}\n",
    );
    write(&ws, "crates/core/src/tests.rs", "#[test]\nfn t() {}\n");
    // The daemon: a workspace dependency, and the test feature of the
    // system library for its tests, as envcloakd's are (and the CLI's).
    write(
        &ws,
        "crates/daemon/Cargo.toml",
        &format!(
            "{}\n[dependencies]\nfx-core.workspace = true\n\n\
             [dev-dependencies]\nfx-sys = {{ path = \"../sys\", features = [\"testing\"] }}\n",
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
    write(&ws, "crates/other/Cargo.toml", &package("fx-other"));
    write(&ws, "crates/other/src/lib.rs", "pub fn other() {}\n");
    (t, ws)
}

/// Changes `rel` so that its modification time is after `bin`'s: now, or
/// just after the binary's when the clock has not moved on since it was
/// linked (file times can be coarser than the clock).
fn edit(ws: &Path, rel: &str, bin: &Path) {
    let path = ws.join(rel);
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("// changed\n");
    std::fs::write(&path, text).unwrap();
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
