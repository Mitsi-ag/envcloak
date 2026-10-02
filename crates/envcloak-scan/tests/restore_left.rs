//! Writing a file back from a backup v2 (SPEC §6.4, R-M2-73: a restore
//! writes a file back "only while it is what the change left"): the file
//! is replaced only while its SHA-256 is the one the daemon recorded after
//! the change, only while it is still the file hashed when the new one
//! takes its name, and only with contents that came whole and have the
//! backed-up SHA-256. Nothing else is ever written in its place, and no
//! temporary file is left.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

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
