//! Real git object storage is the oracle, including an unreachable/deleted blob.
#![allow(clippy::unwrap_used)]
use envcloak_scan::{candidates::Budget, git::scan_git_history, open_root};
use std::process::Command;
fn git(dir: &std::path::Path, args: &[&str]) {
    let o = Command::new("/usr/bin/git")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("HOME", dir)
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(o.status.success(), "git fixture preparation");
}
#[test]
fn deleted_history_is_found_and_limits_are_partial() {
    if std::env::var_os("EC_GIT_CHILD").is_some() {
        return;
    }
    let dir =
        tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).expect("temporary root"))
            .unwrap();
    git(dir.path(), &["init", "-q"]);
    std::fs::write(dir.path().join("gone"), b"fixtureZdeletedHistoryToken").unwrap();
    git(dir.path(), &["add", "gone"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    );
    git(dir.path(), &["rm", "-q", "gone"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "deleted",
        ],
    );
    let root = open_root(dir.path()).unwrap();
    let mut found = false;
    let report = scan_git_history(&root, Budget::default(), &mut |c| {
        found |= c.value.ct_eq(b"fixtureZdeletedHistoryToken");
        true
    })
    .unwrap();
    assert!(report.complete(), "{report:?}");
    assert!(found);
    let report = scan_git_history(
        &root,
        Budget {
            bytes: 10,
            ..Budget::default()
        },
        &mut |_| true,
    )
    .unwrap();
    assert!(!report.complete());
    let report = scan_git_history(
        &root,
        Budget {
            objects: 1,
            ..Budget::default()
        },
        &mut |_| true,
    )
    .unwrap();
    assert!(!report.complete());
    let empty = dir.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["git_environment_child", "--exact", "--nocapture"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("EC_GIT_CHILD", dir.path())
        .env("GIT_OBJECT_DIRECTORY", empty)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "extensions.objectFormat")
        .env("GIT_CONFIG_VALUE_0", "invalid")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "inherited git environment influenced the scan"
    );
}
#[test]
fn git_environment_child() {
    let Some(path) = std::env::var_os("EC_GIT_CHILD") else {
        return;
    };
    let root = open_root(std::path::Path::new(&path)).unwrap();
    let mut found = false;
    let report = scan_git_history(&root, Budget::default(), &mut |c| {
        found |= c.value.ct_eq(b"fixtureZdeletedHistoryToken");
        true
    })
    .unwrap();
    assert!(found && report.complete());
}

#[test]
fn git_scans_the_held_root_after_its_path_is_replaced() {
    let d =
        tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).expect("temporary root"))
            .unwrap();
    let path = d.path().join("repo");
    std::fs::create_dir(&path).unwrap();
    git(&path, &["init", "-q"]);
    std::fs::write(path.join("original"), b"fixtureZoriginalRepository").unwrap();
    git(&path, &["add", "original"]);
    let root = open_root(&path).unwrap();
    std::fs::rename(&path, d.path().join("held")).unwrap();
    std::fs::create_dir(&path).unwrap();
    git(&path, &["init", "-q"]);
    let mut found = false;
    let report = scan_git_history(&root, Budget::default(), &mut |c| {
        found |= c.value.ct_eq(b"fixtureZoriginalRepository");
        true
    })
    .unwrap();
    assert!(report.complete());
    assert!(found, "git reopened a replaced path");
}
