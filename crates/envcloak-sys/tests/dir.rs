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
    DirEntryKind, InUse, MAX_DIR_ENTRIES, Volume, create_beneath, create_dir_beneath,
    exchange_beneath, kind_beneath, link_beneath, list_dir, open_dir_beneath, open_elsewhere,
    read_link_beneath, remove_dir_beneath, rename_beneath, unlink_beneath, volume_of,
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

/// `remove_dir_beneath` removes an empty directory by its name in the
/// directory held open, never one with anything left in it, never a
/// symlink in its place (nor what it points at) and never a file.
#[test]
fn remove_dir_beneath_removes_only_an_empty_directory() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::create_dir(tmp.path().join("empty")).unwrap();
    std::fs::create_dir(tmp.path().join("full")).unwrap();
    std::fs::write(tmp.path().join("full").join("kept"), b"").unwrap();
    std::fs::create_dir(tmp.path().join("target")).unwrap();
    symlink("target", tmp.path().join("link")).unwrap();
    std::fs::write(tmp.path().join("file"), b"").unwrap();
    let dir = File::open(tmp.path()).unwrap();
    remove_dir_beneath(&dir, OsStr::new("empty")).unwrap();
    assert!(!tmp.path().join("empty").exists());
    let e = remove_dir_beneath(&dir, OsStr::new("full")).unwrap_err();
    assert!(
        matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)),
        "{e}"
    );
    assert!(tmp.path().join("full").join("kept").exists());
    for name in ["link", "file"] {
        let e = remove_dir_beneath(&dir, OsStr::new(name)).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENOTDIR), "{name}: {e}");
    }
    assert!(tmp.path().join("link").symlink_metadata().is_ok());
    assert!(tmp.path().join("target").is_dir());
    let e = remove_dir_beneath(&dir, OsStr::new("gone")).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    for name in ["", ".", "..", "full/kept", "a\0b"] {
        let e = remove_dir_beneath(&dir, OsStr::new(name)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{name:?}");
    }
}

/// `create_dir_beneath` makes a directory in the directory held open,
/// with the mode it is given: with that directory's path moved and a
/// symlink to another directory in its place, the new directory is in the
/// one held open, and nothing is made in the other. An existing name, a
/// dangling symlink included, is refused, and nothing is made where it
/// points.
#[test]
fn create_dir_beneath_makes_the_directory_in_the_one_held_open() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let held = tmp.path().join("held");
    let other = tmp.path().join("other");
    std::fs::create_dir(&held).unwrap();
    std::fs::create_dir(&other).unwrap();
    let dir = File::open(&held).unwrap();
    let moved = tmp.path().join("moved");
    std::fs::rename(&held, &moved).unwrap();
    symlink(&other, &held).unwrap();
    create_dir_beneath(&dir, OsStr::new("made"), 0o700).unwrap();
    let m = std::fs::symlink_metadata(moved.join("made")).unwrap();
    assert!(m.is_dir());
    assert_eq!(m.permissions().mode() & 0o777, 0o700);
    assert!(
        std::fs::read_dir(&other).unwrap().next().is_none(),
        "a directory was made through the path, not the handle"
    );
    let e = create_dir_beneath(&dir, OsStr::new("made"), 0o700).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists);
    symlink(tmp.path().join("nowhere"), moved.join("dangling")).unwrap();
    let e = create_dir_beneath(&dir, OsStr::new("dangling"), 0o700).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AlreadyExists);
    assert!(!tmp.path().join("nowhere").exists());
    for name in ["", ".", "..", "made/sub", "a\0b"] {
        let e = create_dir_beneath(&dir, OsStr::new(name), 0o700).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{name:?}");
    }
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
fn kind_and_link_target_beneath_never_follow_a_symlink() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let p = tmp.path();
    std::fs::create_dir(p.join("sub")).unwrap();
    std::fs::write(p.join("file"), b"").unwrap();
    symlink("sub", p.join("dirlink")).unwrap();
    symlink("file", p.join("filelink")).unwrap();
    symlink("/nowhere/at/all", p.join("dangling")).unwrap();
    symlink("loop", p.join("loop")).unwrap();
    // A target longer than the first buffer, with a multi-byte character
    // across its boundary.
    let long: String = "é".repeat(500);
    symlink(&long, p.join("long")).unwrap();
    let fifo = p.join("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let dir = File::open(p).unwrap();
    for (name, kind) in [
        ("sub", DirEntryKind::Dir),
        ("file", DirEntryKind::File),
        ("dirlink", DirEntryKind::Symlink),
        ("filelink", DirEntryKind::Symlink),
        ("dangling", DirEntryKind::Symlink),
        ("loop", DirEntryKind::Symlink),
        ("fifo", DirEntryKind::Other),
    ] {
        assert_eq!(
            kind_beneath(&dir, OsStr::new(name)).unwrap(),
            kind,
            "{name}"
        );
    }
    assert_eq!(
        kind_beneath(&dir, OsStr::new("missing"))
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    for (name, target) in [
        ("dirlink", "sub"),
        ("dangling", "/nowhere/at/all"),
        ("loop", "loop"),
        ("long", long.as_str()),
    ] {
        assert_eq!(
            read_link_beneath(&dir, OsStr::new(name)).unwrap(),
            OsStr::new(target),
            "{name}"
        );
    }
    // Not a symlink: refused, not read through.
    for name in ["file", "sub", "fifo"] {
        let e = read_link_beneath(&dir, OsStr::new(name)).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL), "{name}: {e}");
    }
    for name in ["", ".", "..", "sub/x", "a\0b"] {
        for e in [
            kind_beneath(&dir, OsStr::new(name)).unwrap_err(),
            read_link_beneath(&dir, OsStr::new(name)).unwrap_err(),
        ] {
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{name:?}");
        }
    }
    // Relative to the handle: after the directory moves, the names are
    // still read in it, and its old path now leads nowhere.
    let moved = tempfile::tempdir_in("/tmp").unwrap();
    let new_home = moved.path().join("here");
    std::fs::rename(p, &new_home).unwrap();
    std::fs::create_dir(p).unwrap();
    assert_eq!(
        read_link_beneath(&dir, OsStr::new("dirlink")).unwrap(),
        OsStr::new("sub")
    );
    assert_eq!(
        kind_beneath(&dir, OsStr::new("sub")).unwrap(),
        DirEntryKind::Dir
    );
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

/// A swap exchanges two names in one step, keeps each file whole, needs
/// both names, and never follows a symlink in either place. The file
/// systems the tests run on (APFS, ext4, tmpfs) can swap.
#[test]
fn exchange_swaps_two_names_in_the_handle() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let dir = File::open(tmp.path()).unwrap();
    std::fs::write(tmp.path().join("a"), b"first").unwrap();
    std::fs::write(tmp.path().join("b"), b"second").unwrap();
    let ino = |n: &str| std::fs::metadata(tmp.path().join(n)).unwrap().ino();
    let (a, b) = (ino("a"), ino("b"));
    exchange_beneath(&dir, OsStr::new("a"), OsStr::new("b")).unwrap();
    assert_eq!(std::fs::read(tmp.path().join("a")).unwrap(), b"second");
    assert_eq!(std::fs::read(tmp.path().join("b")).unwrap(), b"first");
    assert_eq!((ino("a"), ino("b")), (b, a));
    // Both names must be there.
    let e = exchange_beneath(&dir, OsStr::new("a"), OsStr::new("missing")).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert_eq!(std::fs::read(tmp.path().join("a")).unwrap(), b"second");
    // A symlink is swapped as a name; its target is not touched.
    std::fs::write(tmp.path().join("target"), b"t").unwrap();
    symlink("target", tmp.path().join("link")).unwrap();
    exchange_beneath(&dir, OsStr::new("a"), OsStr::new("link")).unwrap();
    assert!(
        std::fs::symlink_metadata(tmp.path().join("a"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(tmp.path().join("link")).unwrap(), b"second");
    assert_eq!(std::fs::read(tmp.path().join("target")).unwrap(), b"t");
    for bad in ["", ".", "..", "a/b", "x\0"] {
        let e = exchange_beneath(&dir, OsStr::new(bad), OsStr::new("b")).unwrap_err();
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

/// `open_elsewhere`, looked at again for up to a second while it says
/// open: a holder that exited may take a moment to be reaped, and a
/// sibling test's child holds this binary's descriptors between its fork
/// and its exec.
fn settled(f: &File) -> InUse {
    for _ in 0..20 {
        let got = open_elsewhere(f);
        if got != InUse::Yes {
            return got;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    InUse::Yes
}

#[test]
fn open_elsewhere_sees_another_process_holding_the_file() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let path = tmp.path().join("held");
    std::fs::write(&path, b"x").unwrap();
    let f = File::open(&path).unwrap();
    // No one else has it open. A system that cannot tell says so, and
    // never claims the file is free when it is not (checked below).
    let alone = settled(&f);
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        assert_eq!(alone, InUse::No);
    }
    let mut child = holder(&path);
    assert_eq!(open_elsewhere(&f), InUse::Yes);
    drop(child.stdin.take());
    child.wait().unwrap();
    assert_eq!(settled(&f), InUse::No);
    // The check leaves the descriptor usable.
    let mut s = String::new();
    (&f).read_to_string(&mut s).unwrap();
    assert_eq!(s, "x");
}

/// Review finding F-50: the question is about the open file, not a path
/// remembered for it. The directory holding a file another process has
/// open is renamed, and an empty file takes the old path: the file is
/// still seen open where it is now, and the file at the old path, which
/// no one holds, is not.
#[test]
fn open_elsewhere_follows_the_file_when_its_directory_is_renamed() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let dir = tmp.path().join("root");
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join(".env");
    std::fs::write(&path, b"x").unwrap();
    let f = File::open(&path).unwrap();
    let mut child = holder(&path);
    std::fs::rename(&dir, tmp.path().join("moved")).unwrap();
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(&path, b"").unwrap();
    assert_eq!(open_elsewhere(&f), InUse::Yes);
    let decoy = File::open(&path).unwrap();
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        assert_eq!(settled(&decoy), InUse::No);
    }
    drop(child.stdin.take());
    child.wait().unwrap();
    assert_eq!(settled(&f), InUse::No);
}
