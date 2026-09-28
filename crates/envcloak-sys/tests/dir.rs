//! Names beneath an open directory (SPEC §6.4 "Filesystem safety"):
//! listing, opening a subdirectory, and creating, linking, renaming and
//! removing a name, each relative to a directory the caller holds open and
//! never through a symlink; which kind of volume a directory is on; and
//! whether another process has a file open.
#![allow(clippy::unwrap_used)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, symlink};
use std::process::{Command, Stdio};

use envcloak_sys::{
    DirEntryKind, MAX_DIR_ENTRIES, Volume, create_beneath, link_beneath, list_dir,
    open_dir_beneath, open_elsewhere, rename_beneath, unlink_beneath, volume_of,
};

fn names(dir: &File) -> Vec<(OsString, DirEntryKind)> {
    let mut v: Vec<(OsString, DirEntryKind)> = list_dir(dir, MAX_DIR_ENTRIES)
        .unwrap()
        .into_iter()
        .map(|e| (e.name, e.kind))
        .collect();
    v.sort();
    v
}

#[test]
fn list_dir_names_every_entry_but_dot_and_dot_dot() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::write(tmp.path().join("file"), b"x").unwrap();
    std::fs::create_dir(tmp.path().join("sub")).unwrap();
    symlink("file", tmp.path().join("link")).unwrap();
    // A name with a multi-byte character is listed as it is.
    let odd = OsStr::new(std::str::from_utf8(b"caf\xc3\xa9").unwrap()).to_owned();
    std::fs::write(tmp.path().join(&odd), b"").unwrap();
    let dir = File::open(tmp.path()).unwrap();
    let got = names(&dir);
    let listed: Vec<&OsStr> = got.iter().map(|(n, _)| n.as_os_str()).collect();
    assert_eq!(listed.len(), 4, "{got:?}");
    for n in ["file", "sub", "link"] {
        assert!(listed.contains(&OsStr::new(n)), "{n}");
    }
    assert!(listed.contains(&odd.as_os_str()));
    for (n, k) in &got {
        // readdir's type is a hint: a file system may not give one.
        let expect = match n.to_str() {
            Some("sub") => DirEntryKind::Dir,
            Some("link") => DirEntryKind::Symlink,
            _ => DirEntryKind::File,
        };
        assert!(*k == expect || *k == DirEntryKind::Unknown, "{n:?}: {k:?}");
    }
    // Listing twice gives the same names: the handle's offset is not used
    // up by the first listing.
    assert_eq!(names(&dir), got);
}

#[test]
fn list_dir_stops_at_its_cap() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    for i in 0..10 {
        std::fs::write(tmp.path().join(format!("f{i}")), b"").unwrap();
    }
    let dir = File::open(tmp.path()).unwrap();
    let e = list_dir(&dir, 9).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::OutOfMemory);
    assert_eq!(list_dir(&dir, 10).unwrap().len(), 10);
}

#[test]
fn open_dir_beneath_never_follows_a_symlink() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::create_dir(tmp.path().join("sub")).unwrap();
    std::fs::write(tmp.path().join("sub").join("inner"), b"").unwrap();
    std::fs::write(tmp.path().join("file"), b"").unwrap();
    symlink("sub", tmp.path().join("dirlink")).unwrap();
    // A symlink loop: following it would never end.
    symlink("loop", tmp.path().join("loop")).unwrap();
    let dir = File::open(tmp.path()).unwrap();
    let sub = open_dir_beneath(&dir, OsStr::new("sub")).unwrap();
    assert_eq!(names(&sub).len(), 1);
    for name in ["dirlink", "loop"] {
        let e = open_dir_beneath(&dir, OsStr::new(name)).unwrap_err();
        assert!(
            matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)),
            "{name}: {e}"
        );
    }
    let e = open_dir_beneath(&dir, OsStr::new("file")).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::ENOTDIR));
    for name in ["", ".", "..", "sub/inner", "a\0b"] {
        let e = open_dir_beneath(&dir, OsStr::new(name)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{name:?}");
    }
}

#[test]
fn create_link_rename_and_unlink_work_on_names_in_the_handle() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let dir = File::open(tmp.path()).unwrap();
    let mut f = create_beneath(&dir, OsStr::new("new"), 0o600).unwrap();
    f.write_all(b"body").unwrap();
    drop(f);
    let m = std::fs::metadata(tmp.path().join("new")).unwrap();
    assert_eq!(m.mode() & 0o777, 0o600);
    // O_EXCL: an existing name is never opened or truncated.
    let e = create_beneath(&dir, OsStr::new("new"), 0o600).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists);
    // Nor is a symlink in its place followed, even a dangling one.
    symlink("elsewhere", tmp.path().join("dangling")).unwrap();
    let e = create_beneath(&dir, OsStr::new("dangling"), 0o600).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists);
    assert!(!tmp.path().join("elsewhere").exists());

    // link: a second name for the file, refused when the name is taken.
    link_beneath(&dir, OsStr::new("new"), OsStr::new("second")).unwrap();
    assert_eq!(std::fs::read(tmp.path().join("second")).unwrap(), b"body");
    let e = link_beneath(&dir, OsStr::new("new"), OsStr::new("second")).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists);

    // rename replaces the target.
    std::fs::write(tmp.path().join("other"), b"other").unwrap();
    rename_beneath(&dir, OsStr::new("other"), OsStr::new("second")).unwrap();
    assert_eq!(std::fs::read(tmp.path().join("second")).unwrap(), b"other");
    assert!(!tmp.path().join("other").exists());

    // unlink removes the name, and a symlink itself rather than its target.
    unlink_beneath(&dir, OsStr::new("new")).unwrap();
    assert!(!tmp.path().join("new").exists());
    std::fs::write(tmp.path().join("target"), b"t").unwrap();
    symlink("target", tmp.path().join("tl")).unwrap();
    unlink_beneath(&dir, OsStr::new("tl")).unwrap();
    assert_eq!(std::fs::read(tmp.path().join("target")).unwrap(), b"t");
    let e = unlink_beneath(&dir, OsStr::new("new")).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);

    // The handle decides, not the path: after the directory is moved, the
    // names are still made in it.
    let moved = tmp.path().with_extension("moved");
    std::fs::rename(tmp.path(), &moved).unwrap();
    std::fs::create_dir(tmp.path()).unwrap();
    drop(create_beneath(&dir, OsStr::new("late"), 0o600).unwrap());
    assert!(moved.join("late").exists());
    assert!(!tmp.path().join("late").exists());
    std::fs::remove_dir_all(&moved).unwrap();

    for bad in ["", ".", "..", "a/b", "x\0"] {
        let e = create_beneath(&dir, OsStr::new(bad), 0o600).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad:?}");
        let e = unlink_beneath(&dir, OsStr::new(bad)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad:?}");
        let e = rename_beneath(&dir, OsStr::new(bad), OsStr::new("ok")).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad:?}");
        let e = link_beneath(&dir, OsStr::new("ok"), OsStr::new(bad)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad:?}");
    }
}

#[test]
fn create_beneath_applies_the_mode_it_is_given() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let dir = File::open(tmp.path()).unwrap();
    drop(create_beneath(&dir, OsStr::new("a"), 0o644).unwrap());
    // The umask may take bits away, never add them.
    let mode = std::fs::metadata(tmp.path().join("a")).unwrap().mode() & 0o777;
    assert_eq!(mode & !0o644, 0);
}

#[test]
fn a_temporary_directory_is_on_a_local_volume() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let dir = File::open(tmp.path()).unwrap();
    assert_eq!(volume_of(&dir).unwrap(), Volume::Local);
}

/// A child that opens `path`, says `ready`, and holds it open until its
/// standard input closes.
fn holder(path: &std::path::Path) -> std::process::Child {
    let mut c = Command::new("/bin/sh")
        .arg("-c")
        .arg("exec 3<\"$1\"; echo ready; read x")
        .arg("sh")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(c.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "ready\n");
    c
}

#[test]
fn open_elsewhere_sees_another_process_holding_the_file() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let path = tmp.path().join("held");
    std::fs::write(&path, b"x").unwrap();
    let f = File::open(&path).unwrap();
    // No one else has it open. A system that cannot tell says so, and
    // never claims the file is free when it is not (checked below).
    let alone = open_elsewhere(&f, &path);
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        assert_eq!(alone, Some(false));
    }
    let mut child = holder(&path);
    assert_eq!(open_elsewhere(&f, &path), Some(true));
    drop(child.stdin.take());
    child.wait().unwrap();
    assert_eq!(open_elsewhere(&f, &path), Some(false));
    // The check leaves the descriptor usable.
    let mut s = String::new();
    (&f).read_to_string(&mut s).unwrap();
    assert_eq!(s, "x");
}
