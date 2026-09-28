//! Replacing, creating and removing files under a scan root (SPEC §6.4):
//! only the file that was read is changed, a crash leaves the old file or
//! the new one, and a file is removed only when it is old enough and open
//! nowhere else.
#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use envcloak_scan::{
    FileStamp, MAX_DOTENV, ModifyErrorKind, ScanErrorKind, create_atomically, open_root,
    read_capped, remove_checked, remove_checked_at, replace_atomically,
};

fn age(p: &Path, by: Duration) {
    File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_modified(SystemTime::now() - by)
        .unwrap();
}

fn stamp(p: &Path) -> FileStamp {
    FileStamp::of(&std::fs::metadata(p).unwrap())
}

/// No temporary file is left in `dir`.
fn no_temps(dir: &Path) {
    for e in std::fs::read_dir(dir).unwrap() {
        let n = e.unwrap().file_name();
        assert!(!n.to_string_lossy().contains(".envcloak-"), "{n:?}");
    }
}

#[test]
fn replace_writes_the_new_contents_and_keeps_the_mode() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".gitignore");
    std::fs::write(&p, b"old\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
    let r = open_root(d.path()).unwrap();
    let before = stamp(&p);
    let after = replace_atomically(&r, Path::new(".gitignore"), b"old\nnew\n", &before).unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), b"old\nnew\n");
    assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o640);
    assert_eq!(after, stamp(&p));
    assert_ne!(after.ino, before.ino, "a new file was renamed into place");
    no_temps(d.path());

    // The stamp of the old file no longer matches: nothing is written.
    let e = replace_atomically(&r, Path::new(".gitignore"), b"x", &before).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Changed);
    assert_eq!(std::fs::read(&p).unwrap(), b"old\nnew\n");
    no_temps(d.path());
}

#[test]
fn replace_refuses_a_file_another_program_wrote() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join("envcloak.toml");
    std::fs::write(&p, b"[env]\n").unwrap();
    let r = open_root(d.path()).unwrap();
    let (_, s) = read_capped(&r, Path::new("envcloak.toml"), MAX_DOTENV).unwrap();
    // Same size, new contents, written after the read.
    std::fs::write(&p, b"[xy]\n").unwrap();
    let e = replace_atomically(&r, Path::new("envcloak.toml"), b"new", &s).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Changed);
    assert_eq!(std::fs::read(&p).unwrap(), b"[xy]\n");
    // A file that is gone is changed too.
    std::fs::remove_file(&p).unwrap();
    let e = replace_atomically(&r, Path::new("envcloak.toml"), b"new", &s).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Changed);
    assert!(!p.exists());
    no_temps(d.path());
}

#[test]
fn create_makes_a_new_file_only() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let r = open_root(d.path()).unwrap();
    let s = create_atomically(&r, Path::new("envcloak.toml"), b"[env]\n", 0o644).unwrap();
    let p = d.path().join("envcloak.toml");
    assert_eq!(std::fs::read(&p).unwrap(), b"[env]\n");
    assert_eq!(s, stamp(&p));
    assert_eq!(s.nlink, 1);
    // An existing name is never replaced.
    let e = create_atomically(&r, Path::new("envcloak.toml"), b"other", 0o644).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Exists);
    assert_eq!(std::fs::read(&p).unwrap(), b"[env]\n");
    // Nor is a symlink, dangling or not, followed to create its target.
    symlink(d.path().join("target"), d.path().join(".gitignore")).unwrap();
    let e = create_atomically(&r, Path::new(".gitignore"), b"x", 0o644).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Exists);
    assert!(!d.path().join("target").exists());
    no_temps(d.path());
    // Into a subdirectory, through the handle.
    std::fs::create_dir(d.path().join("sub")).unwrap();
    create_atomically(&r, Path::new("sub/f"), b"1", 0o600).unwrap();
    assert_eq!(std::fs::read(d.path().join("sub/f")).unwrap(), b"1");
    symlink(d.path().join("sub"), d.path().join("via")).unwrap();
    let e = create_atomically(&r, Path::new("via/g"), b"1", 0o600).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Scan(ScanErrorKind::Symlink));
    for bad in ["", "/abs", "../up", "a/../b", "./x"] {
        let e = create_atomically(&r, Path::new(bad), b"1", 0o600).unwrap_err();
        assert_eq!(
            e.kind,
            ModifyErrorKind::Scan(ScanErrorKind::InvalidPath),
            "{bad}"
        );
    }
}

#[test]
fn remove_waits_two_minutes_after_the_last_change() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".env");
    std::fs::write(&p, b"A=1\n").unwrap();
    let r = open_root(d.path()).unwrap();
    let e = remove_checked(&r, Path::new(".env"), &stamp(&p)).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::RecentlyChanged);
    assert!(p.exists());
    // At 119 seconds still too new, at 120 old enough.
    let s = stamp(&p);
    let at = |secs: i64| {
        SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(s.mtime + secs).unwrap())
    };
    let e = remove_checked_at(&r, Path::new(".env"), &s, at(119)).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::RecentlyChanged);
    // A modification time in the future is never old enough.
    let e = remove_checked_at(&r, Path::new(".env"), &s, at(-5)).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::RecentlyChanged);
    remove_checked_at(&r, Path::new(".env"), &s, at(120)).unwrap();
    assert!(!p.exists());
    no_temps(d.path());
}

#[test]
fn remove_takes_only_the_file_that_was_read() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".env");
    std::fs::write(&p, b"A=1\n").unwrap();
    age(&p, Duration::from_secs(600));
    let r = open_root(d.path()).unwrap();
    let (_, s) = read_capped(&r, Path::new(".env"), MAX_DOTENV).unwrap();
    // Saved over (a new inode, as an editor's atomic save makes).
    let fresh = d.path().join("fresh");
    std::fs::write(&fresh, b"A=2\n").unwrap();
    age(&fresh, Duration::from_secs(600));
    std::fs::rename(&fresh, &p).unwrap();
    let e = remove_checked(&r, Path::new(".env"), &s).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Changed);
    assert_eq!(std::fs::read(&p).unwrap(), b"A=2\n");
    // Linked elsewhere since the read.
    let (_, s) = read_capped(&r, Path::new(".env"), MAX_DOTENV).unwrap();
    std::fs::hard_link(&p, d.path().join("copy")).unwrap();
    let e = remove_checked(&r, Path::new(".env"), &s).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Changed);
    let s = stamp(&p);
    let e = remove_checked(&r, Path::new(".env"), &s).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::HardLinked);
    std::fs::remove_file(d.path().join("copy")).unwrap();
    // Gone.
    let s = stamp(&p);
    std::fs::remove_file(&p).unwrap();
    let e = remove_checked(&r, Path::new(".env"), &s).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Changed);
    no_temps(d.path());
}

#[test]
fn remove_refuses_a_file_open_in_another_process() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".env");
    std::fs::write(&p, b"A=1\n").unwrap();
    age(&p, Duration::from_secs(600));
    let r = open_root(d.path()).unwrap();
    let s = stamp(&p);
    let mut holder = Command::new("/bin/sh")
        .arg("-c")
        .arg("exec 3<\"$1\"; echo ready; read x")
        .arg("sh")
        .arg(&p)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(holder.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "ready\n");
    let e = remove_checked(&r, Path::new(".env"), &s).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::OpenElsewhere);
    assert!(p.exists());
    drop(holder.stdin.take());
    holder.wait().unwrap();
    remove_checked(&r, Path::new(".env"), &s).unwrap();
    assert!(!p.exists());
}
