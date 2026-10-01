//! `envcloak-probe-model` never builds with its test hooks (M2 plan §6
//! rule 13): the `testing` feature of envcloak-agents, which hands the
//! scripted model a connection from any peer (`admit_as`) or serves bytes
//! from memory (`serve_bytes`), is enabled only by this crate's own tests,
//! as a dev-dependency. Cargo's own resolver is asked, for a plain root
//! build and for this crate's program, with the dev-dependency edges as the
//! control that shows the check can see the feature.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;

const TESTING: &str = "envcloak-agents feature \"testing\"";

/// `cargo tree`'s view of which envcloak-agents features `selection`
/// enables over the edge kinds `edges`.
fn features(edges: &str, selection: &[&str]) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["tree", "--offline", "--locked", "--prefix", "none"])
        .args(["-e", edges, "-i", "envcloak-agents"])
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
fn release_builds_never_have_the_scripted_model_s_test_hooks() {
    for selection in [&[][..], &["-p", "envcloak-agents"][..]] {
        let tree = features("features,normal", selection);
        assert!(
            tree.contains("envcloak-agents v0.1"),
            "{selection:?}: {tree}"
        );
        assert!(!tree.contains(TESTING), "{selection:?}: {tree}");
    }
    // Control: with dev-dependencies, the feature shows.
    let tree = features("features,normal,dev", &["-p", "envcloak-agents"]);
    assert!(tree.contains(TESTING), "{tree}");
}
