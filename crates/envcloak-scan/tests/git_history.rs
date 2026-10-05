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
