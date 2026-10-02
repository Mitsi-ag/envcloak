//! Writing a file back from a backup v2 (SPEC §6.4, R-M2-73: a restore
//! writes a file back "only while it is what the change left"): the file
//! is replaced only while its SHA-256 is the one the daemon recorded after
//! the change, only while it is still the file hashed when the new one
//! takes its name, and only with contents that came whole and have the
//! backed-up SHA-256. Nothing else is ever written in its place, and no
//! temporary file is left; one a restore killed while it wrote left
//! beside the file goes once the file is written back.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use envcloak_core::SecretBytes;
use envcloak_core::file_backup_v2::{CHUNK_V2, chunk_len};
use envcloak_scan::{
    BackedUpFile, Inside, ModifyErrorKind, ScanErrorKind, open_root, restore_over_left,
    restore_over_left_observed,
};
use sha2::{Digest, Sha256};

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// The original: two chunks, the second short, bytes that are not text.
fn original() -> Vec<u8> {
    (0..CHUNK_V2 + 7).map(|i| (i * 31 % 251) as u8).collect()
}

/// What a change left: shorter, different.
const LEFT: &[u8] = b"PORT=8080\nKEY=[envcloak:redacted:api-key]\n";

/// Chunk `c` of `body`, as a lease's read hands it out.
fn chunk_of(body: &[u8], c: u64) -> SecretBytes {
    let at = c as usize * CHUNK_V2;
    let len = chunk_len(body.len() as u64, c).unwrap();
    SecretBytes::copy_from(&body[at..at + len])
}

fn backed_up(body: &[u8]) -> BackedUpFile {
    BackedUpFile {
        size: body.len() as u64,
        sha256: sha(body),
        sha256_after: sha(LEFT),
    }
}

/// No temporary file is left in `dir`.
fn no_temps(dir: &Path) {
    for e in std::fs::read_dir(dir).unwrap() {
        let n = e.unwrap().file_name();
        assert!(!n.to_string_lossy().contains(".envcloak-"), "{n:?}");
    }
}

/// A file edited after the change (its SHA-256 is not the one the daemon
/// recorded) is kept as it is, `edited_since`, and no chunk is even
/// asked for; the file the change left is replaced by the original, byte
/// for byte, keeping its mode, by a new file renamed into place.
#[test]
fn a_file_is_written_back_only_while_it_is_what_the_change_left() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".mcp.json");
    let body = original();
    let file = backed_up(&body);
    let r = open_root(d.path()).unwrap();
    let mut edited = LEFT.to_vec();
    edited.extend_from_slice(b"ADDED_LATER=1\n");
    std::fs::write(&p, &edited).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
    let mut asked = 0;
    let e = restore_over_left(&r, Path::new(".mcp.json"), &file, &mut |c| {
        asked += 1;
        Some(chunk_of(&body, c))
    })
    .unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::EditedSince);
    assert_eq!(e.kind.token(), "edited_since");
    assert_eq!(
        std::fs::read(&p).unwrap(),
        edited,
        "a file edited after the change was written over"
    );
    assert_eq!(asked, 0);
    no_temps(d.path());

    // Exactly what the change left: written back.
    std::fs::write(&p, LEFT).unwrap();
    let before = std::fs::metadata(&p).unwrap();
    let after = restore_over_left(&r, Path::new(".mcp.json"), &file, &mut |c| {
        Some(chunk_of(&body, c))
    })
    .unwrap();
    assert!(std::fs::read(&p).unwrap() == body, "not byte for byte");
    let now = std::fs::metadata(&p).unwrap();
    assert_eq!(now.mode() & 0o777, 0o640);
    assert_ne!(now.ino(), before.ino(), "a new file was renamed into place");
    assert_eq!(after.ino, now.ino());
    no_temps(d.path());
}

/// A file saved over after it was hashed, before its replacement takes
/// its name, is kept (`changed`): the replacement checks the stamp the
/// file had when it was hashed.
#[test]
fn a_save_after_the_file_was_hashed_is_kept() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join("settings.json");
    let body = original();
    let file = backed_up(&body);
    let r = open_root(d.path()).unwrap();
    std::fs::write(&p, LEFT).unwrap();
    let saved: &[u8] = b"{\"saved\": \"after the hash\"}\n";
    let mut did = false;
    let e = restore_over_left_observed(
        &r,
        Path::new("settings.json"),
        &file,
        &mut |c| Some(chunk_of(&body, c)),
        &mut |at| {
            if at == Inside::Hashed {
                std::fs::write(&p, saved).unwrap();
                did = true;
            }
        },
    )
    .unwrap_err();
    assert!(did);
    assert_eq!(e.kind, ModifyErrorKind::Changed);
    assert_eq!(
        std::fs::read(&p).unwrap(),
        saved,
        "a save after the hash was written over"
    );
    no_temps(d.path());
}

/// A file changed while it is hashed is kept (`changed`) before any chunk
/// is asked for: here it is written over in place with the very bytes the
/// change left, after its stamp was read and before it is read, so its
/// SHA-256 still matches, and only its stamp tells.
#[test]
fn a_file_changed_while_it_is_hashed_is_kept_and_no_chunk_is_read() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join("config.toml");
    let body = original();
    let file = backed_up(&body);
    let r = open_root(d.path()).unwrap();
    std::fs::write(&p, LEFT).unwrap();
    let mut did = false;
    let mut asked = 0;
    let e = restore_over_left_observed(
        &r,
        Path::new("config.toml"),
        &file,
        &mut |c| {
            asked += 1;
            Some(chunk_of(&body, c))
        },
        &mut |at| {
            if at == Inside::Opened {
                let mut w = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
                std::io::Write::write_all(&mut w, LEFT).unwrap();
                w.set_modified(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000),
                )
                .unwrap();
                did = true;
            }
        },
    )
    .unwrap_err();
    assert!(did);
    assert_eq!(e.kind, ModifyErrorKind::Changed);
    assert_eq!(asked, 0, "a chunk was asked for a file that changed");
    assert_eq!(std::fs::read(&p).unwrap(), LEFT);
    no_temps(d.path());
}

/// An edit made in place after the last check is kept (`changed`), never
/// deleted: the edit has the same length as what the change left and its
/// modification time is put back, so the file's device, inode, size and
/// modification time are what was checked, and only its contents (and
/// change time) tell. It is made after the last check, before the names
/// are swapped, and through a descriptor held open, after the swap and
/// before what came out is read. Each time the names are swapped back,
/// the edit has the file's name again, and no temporary file is left.
#[test]
fn an_edit_in_place_after_the_last_check_is_kept() {
    for when in [Inside::Checked, Inside::Exchanged] {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let p = d.path().join(".mcp.json");
        let body = original();
        let file = backed_up(&body);
        let r = open_root(d.path()).unwrap();
        std::fs::write(&p, LEFT).unwrap();
        let mut edit = LEFT.to_vec();
        let at = edit.len() - 2;
        edit[at] ^= 0x20;
        let mut held: Option<std::fs::File> = None;
        let mut did = false;
        let e = restore_over_left_observed(
            &r,
            Path::new(".mcp.json"),
            &file,
            &mut |c| Some(chunk_of(&body, c)),
            &mut |now| {
                if now == Inside::Hashed {
                    held = Some(std::fs::OpenOptions::new().write(true).open(&p).unwrap());
                }
                if now == when {
                    let w = held.as_mut().unwrap();
                    let modified = w.metadata().unwrap().modified().unwrap();
                    std::os::unix::fs::FileExt::write_all_at(w, &edit, 0).unwrap();
                    w.set_modified(modified).unwrap();
                    did = true;
                }
            },
        )
        .unwrap_err();
        assert!(did, "{when:?}");
        assert_eq!(e.kind, ModifyErrorKind::Changed, "{when:?}");
        assert_eq!(
            std::fs::read(&p).unwrap(),
            edit,
            "{when:?}: an edit after the last check was written over"
        );
        no_temps(d.path());
    }
}

/// Contents that do not come whole are never written in the file's place
/// (`backup_unread`): a chunk that does not come, one of another length,
/// and chunks of the right lengths whose whole is not the backed-up
/// SHA-256 (a byte altered). The file stays what the change left, and no
/// temporary file is left.
#[test]
fn contents_that_do_not_come_whole_are_never_written() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".env");
    let body = original();
    let file = backed_up(&body);
    let r = open_root(d.path()).unwrap();
    std::fs::write(&p, LEFT).unwrap();
    type Source = Box<dyn Fn(u64) -> Option<SecretBytes>>;
    let b = body.clone();
    let missing: Source = Box::new(move |c| (c == 0).then(|| chunk_of(&b, c)));
    let b = body.clone();
    let short: Source = Box::new(move |c| {
        let full = chunk_of(&b, c);
        Some(if c == 1 {
            SecretBytes::copy_from(&[0u8; 3])
        } else {
            full
        })
    });
    let b = body.clone();
    let altered: Source = Box::new(move |c| {
        let at = c as usize * CHUNK_V2;
        let len = chunk_len(b.len() as u64, c).unwrap();
        let mut v = b[at..at + len].to_vec();
        if c == 0 {
            v[100] ^= 1;
        }
        Some(SecretBytes::from_vec(v))
    });
    for (what, source) in [
        ("a chunk missing", missing),
        ("a chunk short", short),
        ("a byte altered", altered),
    ] {
        let e = restore_over_left(&r, Path::new(".env"), &file, &mut |c| source(c)).unwrap_err();
        assert_eq!(e.kind, ModifyErrorKind::BackupUnread, "{what}");
        assert_eq!(std::fs::read(&p).unwrap(), LEFT, "{what}: written over");
        no_temps(d.path());
    }
    // A size beyond what any backup holds is refused before anything.
    let huge = BackedUpFile {
        size: u64::MAX,
        ..file
    };
    let e = restore_over_left(&r, Path::new(".env"), &huge, &mut |_| None).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::BackupUnread);
    assert_eq!(std::fs::read(&p).unwrap(), LEFT);
}

/// A file with another hard link is never written over, nor a symlink
/// followed; a file that is gone is not created.
#[test]
fn a_hard_link_a_symlink_or_a_missing_file_is_never_written() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let body = original();
    let file = backed_up(&body);
    let r = open_root(d.path()).unwrap();
    let linked = d.path().join("a.json");
    std::fs::write(&linked, LEFT).unwrap();
    std::fs::hard_link(&linked, d.path().join("b.json")).unwrap();
    let e = restore_over_left(&r, Path::new("a.json"), &file, &mut |c| {
        Some(chunk_of(&body, c))
    })
    .unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::HardLinked);
    assert_eq!(std::fs::read(&linked).unwrap(), LEFT);
    let target = d.path().join("target.json");
    std::fs::write(&target, LEFT).unwrap();
    symlink(&target, d.path().join("link.json")).unwrap();
    let e = restore_over_left(&r, Path::new("link.json"), &file, &mut |c| {
        Some(chunk_of(&body, c))
    })
    .unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Scan(ScanErrorKind::Symlink));
    assert_eq!(std::fs::read(&target).unwrap(), LEFT);
    let e = restore_over_left(&r, Path::new("gone.json"), &file, &mut |c| {
        Some(chunk_of(&body, c))
    })
    .unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Scan(ScanErrorKind::NotFound));
    assert!(!d.path().join("gone.json").exists());
    no_temps(d.path());
}

/// Names the directory the child below writes back in.
const CRASH_DIR: &str = "ENVCLOAK_TEST_RESTORE_CRASH_DIR";

/// Runs only as the child the test below starts: writes the original
/// back over `.mcp.json` in the directory [`CRASH_DIR`] names, and stops
/// once the first chunk is written, until it is killed.
#[test]
fn restore_crash_child() {
    let Some(dir) = std::env::var_os(CRASH_DIR) else {
        return;
    };
    let body = original();
    let r = open_root(Path::new(&dir)).unwrap();
    let _ = restore_over_left(&r, Path::new(".mcp.json"), &backed_up(&body), &mut |c| {
        if c == 1 {
            println!("@@hold");
            std::io::stdout().flush().unwrap();
            std::thread::sleep(Duration::from_secs(120));
        }
        Some(chunk_of(&body, c))
    });
}

/// A restore killed while it writes (`kill -9`, once its first chunk is
/// written beside the file) leaves the file as the change left it, and
/// its new contents so far beside it under its temporary name, 0600,
/// holding only bytes of what it was writing back, and nothing in its
/// temporary directory. The next restore of the file writes it back byte
/// for byte, with its mode, and removes what the killed one left, so no
/// temporary file stays; a file of another name of the same shape stays.
#[test]
fn a_restore_killed_while_it_writes_leaves_the_file_and_the_next_one_cleans_up() {
    if std::env::var_os(CRASH_DIR).is_some() {
        return;
    }
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".mcp.json");
    std::fs::write(&p, LEFT).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
    let other = d
        .path()
        .join("..settings.json.envcloak-new-0123456789abcdef.tmp");
    std::fs::write(&other, b"not this file's").unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "restore_crash_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(CRASH_DIR, d.path())
        .env("TMPDIR", tmp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let out = BufReader::new(child.stdout.take().unwrap());
    let held = out
        .lines()
        .map_while(Result::ok)
        .any(|l| l.contains("@@hold"));
    assert!(held, "the child never wrote its first chunk");
    child.kill().unwrap();
    child.wait().unwrap();

    assert_eq!(std::fs::read(&p).unwrap(), LEFT, "the file was changed");
    let left: Vec<std::path::PathBuf> = std::fs::read_dir(d.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|q| {
            q.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("..mcp.json.envcloak-new-")
        })
        .collect();
    assert_eq!(left.len(), 1, "{left:?}");
    let m = std::fs::metadata(&left[0]).unwrap();
    assert_eq!(m.mode() & 0o777, 0o600);
    assert!(
        std::fs::read(&left[0]).unwrap() == body_prefix(CHUNK_V2),
        "the leftover holds other bytes than the first chunk"
    );
    assert!(std::fs::read_dir(tmp.path()).unwrap().next().is_none());

    let body = original();
    let r = open_root(d.path()).unwrap();
    restore_over_left(&r, Path::new(".mcp.json"), &backed_up(&body), &mut |c| {
        Some(chunk_of(&body, c))
    })
    .unwrap();
    assert!(std::fs::read(&p).unwrap() == body, "not byte for byte");
    assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o640);
    assert!(!left[0].exists(), "the killed restore's file was left");
    assert_eq!(std::fs::read(&other).unwrap(), b"not this file's");
    std::fs::remove_file(&other).unwrap();
    no_temps(d.path());
}

/// The first `n` bytes of [`original`].
fn body_prefix(n: usize) -> Vec<u8> {
    original()[..n].to_vec()
}
