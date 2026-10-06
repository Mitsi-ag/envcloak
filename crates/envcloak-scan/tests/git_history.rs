//! Real git object storage is the oracle, including an unreachable/deleted blob.
#![allow(clippy::unwrap_used)]
use envcloak_scan::{candidates::Budget, git::scan_git_history, open_root};
use std::process::Command;

fn object(dir: &std::path::Path, kind: &str, bytes: &[u8]) -> String {
    use std::io::Write;
    let mut child = Command::new("/usr/bin/git")
        .args(["hash-object", "-w", "--stdin", "-t", kind])
        .current_dir(dir)
        .env_clear()
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[test]
fn recoverable_objects_do_not_hide_later_history() {
    let d = tempfile::tempdir_in(std::env::temp_dir()).unwrap();
    git(d.path(), &["init", "-q"]);
    // Git itself supplies OIDs. Pick a late text object, then require both
    // malformed objects to precede it in cat-file's OID order.
    let mut later = None;
    for n in 0..256 {
        let id = object(
            d.path(),
            "blob",
            format!("fixtureZhistoryAfterSkippedBlobs\n{n}").as_bytes(),
        );
        if id.as_bytes()[0] >= b'e' {
            later = Some(id);
            break;
        }
    }
    let later = later.unwrap();
    for prefix in [vec![0xff, 0xfe, 0x80], vec![b'x'; 5000]] {
        let mut earlier = false;
        for n in 0..256 {
            let mut body = prefix.clone();
            body.extend_from_slice(format!("\n{n}").as_bytes());
            if object(d.path(), "blob", &body) < later {
                earlier = true;
                break;
            }
        }
        assert!(earlier);
    }
    let mut found = false;
    let r = scan_git_history(&open_root(d.path()).unwrap(), Budget::default(), &mut |c| {
        found |= c.occurrence.source.object.as_ref() == Some(&later)
            && c.value.ct_eq(b"fixtureZhistoryAfterSkippedBlobs");
        true
    })
    .unwrap();
    assert!(found, "later text object omitted");
    assert!(!r.complete());
    assert!(r.not_scanned >= 2);
    assert!(r.issues.iter().any(|i| i.reason == "invalid_text"));
    assert!(r.issues.iter().any(|i| i.reason == "token_too_large"));
}

#[test]
fn commit_and_tag_messages_are_scanned_and_callback_refusal_stops() {
    let d = tempfile::tempdir_in(std::env::temp_dir()).unwrap();
    git(d.path(), &["init", "-q"]);
    let tree = object(d.path(), "tree", b"");
    let commit = object(d.path(), "commit", format!("tree {tree}\nauthor Fixture <fixture@example.invalid> 0 +0000\ncommitter Fixture <fixture@example.invalid> 0 +0000\n\nfixtureZcommitMessageValue\n").as_bytes());
    let tag = object(d.path(), "tag", format!("object {commit}\ntype commit\ntag fixture\ntagger Fixture <fixture@example.invalid> 0 +0000\n\nfixtureZtagMessageValue\n").as_bytes());
    let root = open_root(d.path()).unwrap();
    let mut found = std::collections::BTreeSet::new();
    let r = scan_git_history(&root, Budget::default(), &mut |c| {
        if c.value.ct_eq(b"fixtureZcommitMessageValue") || c.value.ct_eq(b"fixtureZtagMessageValue")
        {
            assert!(!c.occurrence.rewritable);
            found.insert(c.occurrence.source.object.unwrap());
        }
        true
    })
    .unwrap();
    assert!(r.complete(), "{r:?}");
    assert_eq!(found, std::collections::BTreeSet::from([commit, tag]));
    let mut calls = 0;
    let r = scan_git_history(&root, Budget::default(), &mut |_| {
        calls += 1;
        false
    })
    .unwrap();
    assert_eq!(calls, 1);
    assert!(!r.complete());
    assert!(r.issues.iter().any(|i| i.reason == "candidate_budget"));
}
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
fn damaged_partial_clone_never_uses_its_transport() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir_in("/tmp").unwrap();
    git(dir.path(), &["init", "-q"]);
    let id = object(dir.path(), "blob", b"fixtureZpartialCloneValue");
    let loose = dir
        .path()
        .join(".git/objects")
        .join(&id[..2])
        .join(&id[2..]);
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(loose, b"damaged loose object").unwrap();

    // The remote is local and its transport only records an attempt. No
    // network service or external repository participates in this gate.
    let remote = dir.path().join("remote");
    std::fs::create_dir(&remote).unwrap();
    git(&remote, &["init", "--bare", "-q"]);
    let uploadpack = dir.path().join("record-fetch");
    let marker = dir.path().join("record-fetch.marker");
    std::fs::write(&uploadpack, b"#!/bin/sh\n: > \"$0.marker\"\nexit 1\n").unwrap();
    std::fs::set_permissions(&uploadpack, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (key, value) in [
        ("core.repositoryFormatVersion", "1"),
        ("extensions.partialClone", "origin"),
        ("remote.origin.promisor", "true"),
        ("remote.origin.url", remote.to_str().unwrap()),
        ("remote.origin.uploadpack", uploadpack.to_str().unwrap()),
        // The scanner must override even an explicit repository allowance.
        ("protocol.allow", "always"),
        ("protocol.file.allow", "always"),
    ] {
        git(dir.path(), &["config", key, value]);
    }

    let report = scan_git_history(
        &open_root(dir.path()).unwrap(),
        Budget::default(),
        &mut |_| panic!("damaged object emitted a candidate"),
    )
    .unwrap();
    assert!(!marker.exists(), "history scan invoked a remote transport");
    assert!(!report.complete(), "damaged history reported complete");
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

#[test]
fn history_never_discovers_a_repository_above_the_held_root() {
    let d = tempfile::tempdir_in(std::env::temp_dir()).unwrap();
    git(d.path(), &["init", "-q"]);
    object(d.path(), "blob", b"fixtureZparentRepositoryValue");
    let nested = d.path().join("nested");
    std::fs::create_dir(&nested).unwrap();
    let mut emitted = 0;
    let report = scan_git_history(&open_root(&nested).unwrap(), Budget::default(), &mut |_| {
        emitted += 1;
        true
    })
    .unwrap();
    assert!(!report.complete());
    assert_eq!(emitted, 0);
    assert!(report.issues.iter().any(|i| i.reason == "git_failed"));
    git(&nested, &["init", "-q"]);
    object(&nested, "blob", b"fixtureZlocalRepositoryValue");
    let mut found = false;
    let report = scan_git_history(&open_root(&nested).unwrap(), Budget::default(), &mut |c| {
        assert!(!c.value.ct_eq(b"fixtureZparentRepositoryValue"));
        found |= c.value.ct_eq(b"fixtureZlocalRepositoryValue");
        true
    })
    .unwrap();
    assert!(report.complete());
    assert!(found);
}

#[test]
fn renamed_non_repository_cannot_discover_its_new_parent() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    git(d.path(), &["init", "-q"]);
    object(d.path(), "blob", b"fixtureZparentRepositoryValue");
    let path = d.path().join("before");
    std::fs::create_dir(&path).unwrap();
    let held = open_root(&path).unwrap();
    std::fs::rename(&path, d.path().join("after")).unwrap();
    let report = scan_git_history(&held, Budget::default(), &mut |_| {
        panic!("scanned a parent repository")
    })
    .unwrap();
    assert!(!report.complete());
    assert!(report.issues.iter().any(|i| i.reason == "git_failed"));
}

#[test]
fn explicit_bare_repository_still_scans() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    git(d.path(), &["init", "--bare", "-q"]);
    object(d.path(), "blob", b"fixtureZbareRepositoryValue");
    let mut found = false;
    let report = scan_git_history(&open_root(d.path()).unwrap(), Budget::default(), &mut |c| {
        found |= c.value.ct_eq(b"fixtureZbareRepositoryValue");
        true
    })
    .unwrap();
    assert!(report.complete(), "{report:?}");
    assert!(found);
}

#[test]
fn symlinked_git_directory_is_refused() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let project = d.path().join("project");
    let other = d.path().join("other");
    std::fs::create_dir(&project).unwrap();
    std::fs::create_dir(&other).unwrap();
    git(&other, &["init", "-q"]);
    object(&other, "blob", b"fixtureZsymlinkedGitValue");
    std::os::unix::fs::symlink(other.join(".git"), project.join(".git")).unwrap();
    let report = scan_git_history(
        &open_root(&project).unwrap(),
        Budget::default(),
        &mut |_| panic!("followed a symlinked Git directory"),
    )
    .unwrap();
    assert!(!report.complete());
    assert_eq!(report.bytes, 0);
    assert!(report.issues.iter().any(|i| i.reason == "symlink"));
}

#[test]
fn external_gitfile_store_is_reported() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let project = d.path().join("project");
    std::fs::create_dir(&project).unwrap();
    // Git writes the gitfile, including its absolute path and line ending.
    git(
        &project,
        &[
            "init",
            "-q",
            "--separate-git-dir",
            d.path().join("store").to_str().unwrap(),
        ],
    );
    object(&project, "blob", b"fixtureZexternalGitfileValue");
    let mut found = false;
    let report = scan_git_history(&open_root(&project).unwrap(), Budget::default(), &mut |c| {
        found |= c.value.ct_eq(b"fixtureZexternalGitfileValue");
        true
    })
    .unwrap();
    assert!(found);
    assert!(
        !report.complete(),
        "external gitfile store was not reported"
    );
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.reason == "gitfile_indirection")
    );
}

#[test]
fn invalid_gitfile_still_reports_the_child_failure() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::write(d.path().join(".git"), b"invalid gitfile\n").unwrap();
    let report = scan_git_history(
        &open_root(d.path()).unwrap(),
        Budget::default(),
        &mut |_| panic!("invalid gitfile emitted a candidate"),
    )
    .unwrap();
    assert!(!report.complete());
    for reason in ["gitfile_indirection", "git_failed"] {
        assert!(report.issues.iter().any(|i| i.reason == reason), "{reason}");
    }
}

#[test]
fn external_alternate_store_is_reported() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let other = d.path().join("other");
    std::fs::create_dir(&other).unwrap();
    git(&other, &["init", "-q"]);
    object(&other, "blob", b"fixtureZalternateStoreValue");
    // A real shared clone supplies the alternates file, not this test.
    git(
        d.path(),
        &[
            "clone",
            "--shared",
            "--quiet",
            "--no-checkout",
            "other",
            "project",
        ],
    );
    let project = d.path().join("project");
    assert!(project.join(".git/objects/info/alternates").is_file());
    let mut found = false;
    let report = scan_git_history(&open_root(&project).unwrap(), Budget::default(), &mut |c| {
        found |= c.value.ct_eq(b"fixtureZalternateStoreValue");
        true
    })
    .unwrap();
    assert!(found);
    assert!(
        !report.complete(),
        "external alternate store was not reported"
    );
    assert!(report.issues.iter().any(|i| i.reason == "git_alternates"));
}

#[test]
fn external_common_directory_is_reported() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let project = d.path().join("project");
    let other = d.path().join("other");
    for dir in [&project, &other] {
        std::fs::create_dir(dir).unwrap();
        git(dir, &["init", "-q"]);
    }
    object(&other, "blob", b"fixtureZcommonDirectoryValue");
    // Synthetic metadata fixture for the standalone commondir spelling.
    // The native linked-worktree gate separately covers Git-authored metadata.
    std::fs::write(
        project.join(".git/commondir"),
        format!("{}\n", other.join(".git").display()),
    )
    .unwrap();
    let mut found = false;
    let report = scan_git_history(&open_root(&project).unwrap(), Budget::default(), &mut |c| {
        found |= c.value.ct_eq(b"fixtureZcommonDirectoryValue");
        true
    })
    .unwrap();
    assert!(found);
    assert!(
        !report.complete(),
        "external common directory was not reported"
    );
    assert!(report.issues.iter().any(|i| i.reason == "git_common_dir"));
}

#[test]
fn git_store_symlinks_are_refused_before_object_reads() {
    for relative in [
        "objects",
        "objects/info",
        "objects/info/alternates",
        "commondir",
    ] {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let project = d.path().join("project");
        std::fs::create_dir(&project).unwrap();
        git(&project, &["init", "-q"]);
        object(&project, "blob", b"fixtureZlinkedStoreValue");
        let path = project.join(".git").join(relative);
        if relative == "commondir" {
            std::fs::write(&path, b".\n").unwrap();
        } else if relative == "objects/info/alternates" {
            std::fs::write(&path, b"").unwrap();
        }
        let moved = d.path().join("moved");
        std::fs::rename(&path, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &path).unwrap();
        let report = scan_git_history(
            &open_root(&project).unwrap(),
            Budget::default(),
            &mut |_| panic!("followed a symlinked Git store"),
        )
        .unwrap();
        assert!(!report.complete());
        assert_eq!(report.bytes, 0);
        assert!(
            report.issues.iter().any(|i| i.reason == "symlink"),
            "{relative}"
        );
    }
}

#[test]
fn linked_worktree_uses_its_explicit_git_file() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    git(d.path(), &["init", "-q"]);
    git(
        d.path(),
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
    );
    object(d.path(), "blob", b"fixtureZlinkedWorktreeValue");
    let linked = d.path().join("linked");
    git(
        d.path(),
        &[
            "worktree",
            "add",
            "--detach",
            "--quiet",
            linked.to_str().unwrap(),
        ],
    );
    assert!(linked.join(".git").is_file());
    let mut found = false;
    let report = scan_git_history(&open_root(&linked).unwrap(), Budget::default(), &mut |c| {
        found |= c.value.ct_eq(b"fixtureZlinkedWorktreeValue");
        true
    })
    .unwrap();
    assert!(!report.complete());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.reason == "gitfile_indirection")
    );
    assert!(found);
}
