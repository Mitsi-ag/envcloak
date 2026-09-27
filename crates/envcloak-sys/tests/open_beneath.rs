//! `open_beneath`: opening one name inside an open directory without
//! following a symlink in its place and without blocking on a FIFO.
#![allow(clippy::unwrap_used)]

use std::ffi::OsStr;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::symlink;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use envcloak_sys::open_beneath;

#[test]
fn opens_a_file_in_the_directory_it_is_given() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::write(tmp.path().join("a.toml"), b"one").unwrap();
    let dir = File::open(tmp.path()).unwrap();
    let mut s = String::new();
    open_beneath(&dir, OsStr::new("a.toml"))
        .unwrap()
        .read_to_string(&mut s)
        .unwrap();
    assert_eq!(s, "one");

    // The directory handle, not the path, decides: after the path is moved
    // and another directory put in its place, the handle still reads the
    // original.
    let moved = tmp.path().with_extension("moved");
    std::fs::rename(tmp.path(), &moved).unwrap();
    std::fs::create_dir(tmp.path()).unwrap();
    std::fs::write(tmp.path().join("a.toml"), b"two").unwrap();
    let mut s = String::new();
    open_beneath(&dir, OsStr::new("a.toml"))
        .unwrap()
        .read_to_string(&mut s)
        .unwrap();
    assert_eq!(s, "one");
    std::fs::remove_dir_all(&moved).unwrap();

    let e = open_beneath(&dir, OsStr::new("missing")).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
}

#[test]
fn a_symlink_in_its_place_is_not_followed() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::write(tmp.path().join("real"), b"x").unwrap();
    symlink("real", tmp.path().join("link")).unwrap();
    symlink("missing", tmp.path().join("dangling")).unwrap();
    let dir = File::open(tmp.path()).unwrap();
    for name in ["link", "dangling"] {
        let e = open_beneath(&dir, OsStr::new(name)).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ELOOP), "{name}: {e}");
    }
}

#[test]
fn a_fifo_opens_without_waiting_for_a_writer() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let st = Command::new("/usr/bin/mkfifo")
        .arg(tmp.path().join("fifo"))
        .status()
        .unwrap();
    assert!(st.success());
    let dir = File::open(tmp.path()).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let f = open_beneath(&dir, OsStr::new("fifo"));
        let _ = tx.send(f.map(|f| f.metadata().unwrap().file_type().is_file()));
    });
    let got = rx.recv_timeout(Duration::from_secs(20)).expect("open hung");
    assert!(!got.unwrap());
}

#[test]
fn only_one_plain_name_is_accepted() {
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::create_dir(tmp.path().join("sub")).unwrap();
    std::fs::write(tmp.path().join("sub").join("f"), b"x").unwrap();
    let dir = File::open(tmp.path().join("sub")).unwrap();
    for name in ["", ".", "..", "../sub/f", "sub/f", "/etc/hosts", "f\0"] {
        let e = open_beneath(&dir, OsStr::new(name)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput, "{name:?}");
    }
    // A file descriptor that is not a directory.
    let file = File::open(tmp.path().join("sub").join("f")).unwrap();
    let e = open_beneath(&file, OsStr::new("f")).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::ENOTDIR));
}
