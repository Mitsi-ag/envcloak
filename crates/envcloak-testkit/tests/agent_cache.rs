//! The agent-host cache the harness looks in by default is the one
//! scripts/install-agent-hosts.py installs into by default: following
//! docs/ACCEPTANCE.md's local procedure (install, then run the tests) must
//! find the hosts, not skip every test (review of M2-04).
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use envcloak_testkit::agents::default_cache_dir;

/// `path` with its parent resolved (macOS reaches `/tmp` through a link),
/// for a directory that need not exist yet.
fn resolved(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap();
    std::fs::canonicalize(parent)
        .unwrap_or_else(|_| parent.to_path_buf())
        .join(path.file_name().unwrap())
}

#[test]
fn the_harness_and_the_installer_default_to_the_same_cache() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // The installer as a person runs it from this workspace: the same
    // CARGO_TARGET_DIR this test was built with, if any, and no explicit
    // cache.
    let out = Command::new("python3")
        .arg(root.join("scripts/install-agent-hosts.py"))
        .arg("--print-cache-dir")
        .env_remove("ENVCLOAK_AGENT_HOSTS")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let installer = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim());
    let exe = std::env::current_exe().unwrap();
    let harness = default_cache_dir(&exe).unwrap();
    assert_eq!(resolved(&harness), resolved(&installer));
}
