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

/// The installer never runs a Node that failed its pin check (review
/// F-100): its own self-test, on synthetic pins with downloads from local
/// files and every subprocess recorded instead of run. A cached Node whose
/// bin/node, npm or any other file is not the pinned one, a download that
/// is not the pinned archive and an extracted tree that is not the pinned
/// one each install no npm host and start nothing; a verified Node, cached
/// or downloaded, runs `npm ci` once, with that Node.
#[test]
fn the_installer_runs_npm_only_under_a_node_it_verified() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new("python3")
        .arg(root.join("scripts/install-agent-hosts.py"))
        .arg("--self-test")
        .env_remove("ENVCLOAK_AGENT_HOSTS")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
