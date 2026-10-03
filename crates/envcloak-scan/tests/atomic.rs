//! Replacing, creating and removing files under a scan root (SPEC §6.4):
//! only the file that was read is changed, a crash leaves the old file or
//! the new one, and a file is removed or rewritten only when it is old
//! enough and open nowhere else.
//!
//! A process forked while this one has a file open holds that file until
//! it execs, and would count as having it open. The tests here run one at
//! a time ([`serial`]), so no child of one test holds another's file.
#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use envcloak_scan::{
    FileStamp, Inside, MAX_DOTENV, ModifyErrorKind, ScanErrorKind, create_atomically, open_root,
    read_capped, remove_checked, remove_checked_at, remove_checked_observed, replace_atomically,
    rewrite_checked, rewrite_checked_observed,
};

/// Held for the whole of each test.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write(p: &Path, b: &[u8]) {
    std::fs::write(p, b).unwrap();
}

fn age(p: &Path, by: Duration) {
    File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_modified(SystemTime::now() - by)
        .unwrap();
}

/// A process holding `p` open (read and write) until it is told to go on:
/// then, 300 ms later, it writes `edit` over the start of the file in
/// place, restores the modification time, closes the file and says `done`.
fn holder(p: &Path, edit: &str) -> Child {
    let mut c = Command::new("python3")
        .arg("-c")
        .arg(
            "import os, sys, time\n\
             st = os.stat(sys.argv[1])\n\
             f = open(sys.argv[1], 'r+b')\n\
             print('ready', flush=True)\n\
             sys.stdin.readline()\n\
             time.sleep(0.3)\n\
             if sys.argv[2]:\n\
             \x20   f.write(sys.argv[2].encode())\n\
             \x20   f.flush()\n\
             \x20   os.utime(sys.argv[1], ns=(st.st_atime_ns, st.st_mtime_ns))\n\
             f.close()\n\
             print('done', flush=True)\n",
        )
        .arg(p)
        .arg(edit)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    assert_eq!(line_of(&mut c), "ready\n");
    c
}

fn line_of(c: &mut Child) -> String {
    let mut line = String::new();
    BufReader::new(c.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    line
}

/// Tells a [`holder`] to go on.
fn go(c: &mut Child) {
    c.stdin.as_mut().unwrap().write_all(b"go\n").unwrap();
}

/// Waits for a [`holder`] told to go on to finish.
fn finished(mut c: Child) {
    assert_eq!(line_of(&mut c), "done\n");
    c.wait().unwrap();
}

/// Tells a [`holder`] to go on, and waits for it.
fn release(mut c: Child) {
    go(&mut c);
    finished(c);
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
    let _serial = serial();
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".gitignore");
    write(&p, b"old\n");
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
    let _serial = serial();
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join("envcloak.toml");
    write(&p, b"[env]\n");
    let r = open_root(d.path()).unwrap();
    let (_, s) = read_capped(&r, Path::new("envcloak.toml"), MAX_DOTENV).unwrap();
    // Same size, new contents, written after the read.
    write(&p, b"[xy]\n");
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

/// An editor's atomic save (a new file renamed over the name) that lands
/// after the last check, right before the new contents take the name, is
/// kept: the swap brings it out, it is not the file checked, and the
/// names are swapped back. Nothing is replaced, and no temporary file is
/// left.
#[test]
fn a_save_after_the_last_check_is_never_replaced() {
    let _serial = serial();
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".env");
    write(&p, b"A=1\nPORT=8080\n");
    age(&p, Duration::from_secs(600));
    let r = open_root(d.path()).unwrap();
    let s = stamp(&p);
    let mut saved = false;
    let e = rewrite_checked_observed(
        &r,
        Path::new(".env"),
        b"PORT=8080\n",
        &s,
        SystemTime::now(),
        &mut |at| {
            if at == Inside::Checked {
                let t = d.path().join(".env.swp");
                write(&t, b"A=2\nPORT=8080\n");
                std::fs::rename(&t, &p).unwrap();
                saved = true;
            }
        },
    )
    .unwrap_err();
    assert!(saved);
    assert_eq!(e.kind, ModifyErrorKind::Changed);
    assert_eq!(e.rel, Path::new(".env"));
    assert_eq!(std::fs::read(&p).unwrap(), b"A=2\nPORT=8080\n");
    no_temps(d.path());
    // Unsaved over, the same rewrite goes through.
    age(&p, Duration::from_secs(600));
    let s = stamp(&p);
    rewrite_checked(&r, Path::new(".env"), b"PORT=8080\n", &s).unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), b"PORT=8080\n");
    no_temps(d.path());
}

#[test]
fn create_makes_a_new_file_only() {
    let _serial = serial();
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
    let _serial = serial();
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".env");
    write(&p, b"A=1\n");
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
    let _serial = serial();
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".env");
    write(&p, b"A=1\n");
    age(&p, Duration::from_secs(600));
    let r = open_root(d.path()).unwrap();
    let (_, s) = read_capped(&r, Path::new(".env"), MAX_DOTENV).unwrap();
    // Saved over (a new inode, as an editor's atomic save makes).
    let fresh = d.path().join("fresh");
    write(&fresh, b"A=2\n");
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

/// A file that is not the one checked once it moved aside is put back
/// under its name, and the name it moved to goes only while it names that
/// same file (verifier, M2-05 round 11: it was unlinked whatever it named).
/// Once `.env` is moved aside (a barrier at `MovedAside`), another program
/// writes into it there, so it is not the file checked; once it is linked
/// back (a barrier at `PutBack`), another program renames its own file onto
/// the name it moved to. That file stays, and is named (`moved_aside`);
/// `.env` keeps its name, as written into. And when the file is gone from
/// where it moved (removed there by another program), nothing is named
/// (`changed`) and nothing is left under a temporary name.
#[test]
fn a_file_renamed_onto_a_removals_name_once_put_back_stays() {
    let _serial = serial();
    for case in ["put back", "gone"] {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let p = d.path().join(".env");
        write(&p, b"A=1\n");
        age(&p, Duration::from_secs(600));
        let r = open_root(d.path()).unwrap();
        let (_, s) = read_capped(&r, Path::new(".env"), MAX_DOTENV).unwrap();
        let mut aside = None;
        let mut put_back = 0;
        let e =
            remove_checked_observed(
                &r,
                Path::new(".env"),
                &s,
                SystemTime::now(),
                &mut |at| match at {
                    Inside::MovedAside => {
                        let n = std::fs::read_dir(d.path())
                            .unwrap()
                            .map(|e| e.unwrap().file_name().into_string().unwrap())
                            .find(|n| n.starts_with("..env.envcloak-del-"))
                            .unwrap();
                        let q = d.path().join(&n);
                        if case == "gone" {
                            std::fs::remove_file(&q).unwrap();
                        } else {
                            let mut w = File::options().append(true).open(&q).unwrap();
                            w.write_all(b"B=2\n").unwrap();
                        }
                        aside = Some(q);
                    }
                    Inside::PutBack => {
                        let other = d.path().join("another");
                        write(&other, b"another program's file");
                        std::fs::rename(&other, aside.as_ref().unwrap()).unwrap();
                        put_back += 1;
                    }
                    _ => {}
                },
            )
            .unwrap_err();
        let aside = aside.expect("never moved aside");
        if case == "gone" {
            assert_eq!(put_back, 0);
            assert_eq!(e.kind, ModifyErrorKind::Changed);
            assert_eq!(e.rel, Path::new(".env"));
            assert!(!p.exists());
            no_temps(d.path());
        } else {
            assert_eq!(put_back, 1, "never put back");
            assert_eq!(e.kind, ModifyErrorKind::MovedAside);
            assert_eq!(d.path().join(&e.rel), aside);
            assert_eq!(
                std::fs::read(&aside).unwrap(),
                b"another program's file",
                "the file renamed onto the name was removed"
            );
            assert_eq!(std::fs::read(&p).unwrap(), b"A=1\nB=2\n");
        }
    }
}

#[test]
fn remove_refuses_a_file_open_in_another_process() {
    let _serial = serial();
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".env");
    write(&p, b"A=1\n");
    age(&p, Duration::from_secs(600));
    let r = open_root(d.path()).unwrap();
    let s = stamp(&p);
    let h = holder(&p, "");
    let e = remove_checked(&r, Path::new(".env"), &s).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::OpenElsewhere);
    let e = rewrite_checked(&r, Path::new(".env"), b"B=2\n", &s).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::OpenElsewhere);
    assert_eq!(std::fs::read(&p).unwrap(), b"A=1\n");
    release(h);
    remove_checked(&r, Path::new(".env"), &s).unwrap();
    assert!(!p.exists());
    no_temps(d.path());
}

/// Review finding F-51: a file found open is kept at once, never waited
/// for. Its holder, told to go on just before the removal, edits it in
/// place 300 ms later, keeping its size and putting its modification time
/// back, and closes it: its bytes stay on disk, and the stamp read before
/// (whose change time no longer matches) removes nothing. (A removal that
/// waited for the holder to close, as one did, removed the new bytes.)
#[test]
fn a_file_edited_in_place_by_its_holder_is_never_removed() {
    let _serial = serial();
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".env");
    write(&p, b"A=1\n");
    age(&p, Duration::from_secs(600));
    let r = open_root(d.path()).unwrap();
    let (_, s) = read_capped(&r, Path::new(".env"), MAX_DOTENV).unwrap();
    let mut h = holder(&p, "A=2");
    go(&mut h);
    let e = remove_checked(&r, Path::new(".env"), &s).unwrap_err();
    // Open when asked; changed, had the machine been slow enough to ask
    // only after the edit.
    assert!(
        matches!(
            e.kind,
            ModifyErrorKind::OpenElsewhere | ModifyErrorKind::Changed
        ),
        "{e:?}"
    );
    finished(h);
    assert_eq!(std::fs::read(&p).unwrap(), b"A=2\n");
    let now = stamp(&p);
    assert_eq!(
        (now.size, now.mtime, now.mtime_nsec),
        (s.size, s.mtime, s.mtime_nsec)
    );
    assert_ne!((now.ctime, now.ctime_nsec), (s.ctime, s.ctime_nsec));
    for e in [
        remove_checked(&r, Path::new(".env"), &s).unwrap_err(),
        rewrite_checked(&r, Path::new(".env"), b"", &s)
            .map(drop)
            .unwrap_err(),
    ] {
        assert_eq!(e.kind, ModifyErrorKind::Changed);
    }
    assert_eq!(std::fs::read(&p).unwrap(), b"A=2\n");
    no_temps(d.path());
}

/// Review finding F-50: the root's directory is renamed while another
/// process holds the file open, and an empty file takes the old path. The
/// file, reached through the root's handle, is still seen open, and kept.
#[test]
fn a_renamed_root_still_keeps_a_file_open_elsewhere() {
    let _serial = serial();
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let root = d.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let p = root.join(".env");
    write(&p, b"A=1\n");
    age(&p, Duration::from_secs(600));
    let r = open_root(&root).unwrap();
    let s = stamp(&p);
    let h = holder(&p, "");
    std::fs::rename(&root, d.path().join("moved")).unwrap();
    std::fs::create_dir(&root).unwrap();
    write(&p, b"");
    for e in [
        remove_checked(&r, Path::new(".env"), &s).unwrap_err(),
        rewrite_checked(&r, Path::new(".env"), b"", &s)
            .map(drop)
            .unwrap_err(),
    ] {
        assert_eq!(e.kind, ModifyErrorKind::OpenElsewhere);
    }
    assert_eq!(
        std::fs::read(d.path().join("moved/.env")).unwrap(),
        b"A=1\n"
    );
    release(h);
    remove_checked(&r, Path::new(".env"), &s).unwrap();
    assert!(!d.path().join("moved/.env").exists());
    assert!(p.exists(), "the file at the old path is another one");
}

/// A rewrite follows the rules of a removal, then replaces the file whole
/// with its mode kept.
#[test]
fn rewrite_replaces_only_an_old_file_no_one_holds() {
    let _serial = serial();
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".env");
    write(&p, b"A=1\nPORT=8080\n");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let r = open_root(d.path()).unwrap();
    let e = rewrite_checked(&r, Path::new(".env"), b"PORT=8080\n", &stamp(&p)).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::RecentlyChanged);
    age(&p, Duration::from_secs(600));
    let s = stamp(&p);
    let after = rewrite_checked(&r, Path::new(".env"), b"PORT=8080\n", &s).unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), b"PORT=8080\n");
    assert_eq!(after, stamp(&p));
    assert_eq!(after.mode & 0o777, 0o600);
    assert_ne!(after.ino, s.ino);
    // The old stamp names nothing any more.
    let e = rewrite_checked(&r, Path::new(".env"), b"", &s).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Changed);
    no_temps(d.path());
}
