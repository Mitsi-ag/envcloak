//! Shipped binaries never build with test-only features. envcloak-testkit
//! needs envcloak-sys's `testing` feature (the inspection allocator and the
//! ptrace helpers); if a root `cargo build --release` unified it into
//! `envcloak` and `envcloakd`, release artifacts would carry that code. The
//! workspace's default members leave the testkit out. Cargo's own resolver is
//! asked, for a plain root build and for the two binaries, with the whole
//! workspace as the control that shows the check can see the feature.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;

/// `cargo tree`'s view of which envcloak-sys features a build enables.
fn sys_features(selection: &[&str]) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["tree", "--offline", "--locked", "--prefix", "none"])
        .args(["-e", "features,normal", "-i", "envcloak-sys"])
        .args(selection)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn release_builds_never_enable_test_only_features() {
    let testing = "envcloak-sys feature \"testing\"";
    for selection in [&[][..], &["-p", "envcloak", "-p", "envcloakd"][..]] {
        let tree = sys_features(selection);
        assert!(tree.contains("envcloak v0.1"), "{selection:?}: {tree}");
        assert!(tree.contains("envcloakd v0.1"), "{selection:?}: {tree}");
        assert!(!tree.contains(testing), "{selection:?}: {tree}");
    }
    // Control: with the testkit selected, the feature shows.
    let tree = sys_features(&["--workspace"]);
    assert!(tree.contains(testing), "{tree}");
}
