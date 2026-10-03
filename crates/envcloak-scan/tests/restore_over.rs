//! Writing a file back from an `init` backup (SPEC §6.4, F-78: `envcloak
//! init --undo` puts back a rewritten file "only while it is what the
//! deletion left"): the file is replaced only while its SHA-256 is the
//! one the backup recorded of the rewrite, only while it is still the
//! file hashed when the original takes its name, and only while what the
//! swap brought out still holds those bytes. An edit made in place after
//! the last check, at the same length with its modification time put
//! back, is kept, and no temporary file is left.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use envcloak_core::SecretBytes;
use envcloak_scan::{Inside, ModifyErrorKind, open_root, restore_over, restore_over_observed};
use sha2::{Digest, Sha256};

/// What the deletion left of the file.
const LEFT: &[u8] = b"PORT=8080\nMODE=production\n";

/// The original, as the backup holds it.
const ORIGINAL: &[u8] = b"TOKEN=from the backup, not a key\nPORT=8080\nMODE=production\n";

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// No temporary file is left in `dir`.
fn no_temps(dir: &Path) {
    for e in std::fs::read_dir(dir).unwrap() {
        let n = e.unwrap().file_name();
        assert!(!n.to_string_lossy().contains(".envcloak-"), "{n:?}");
    }
}

/// A file edited after the deletion (its SHA-256 is not the one the
/// backup recorded) is kept as it is (`edited_since`); the file exactly
/// as the deletion left it is replaced by the original, byte for byte,
/// keeping its mode, by a new file put in its place.
///
/// Mutation: the hash before the write left out (the edited file is
/// written over).
#[test]
fn a_file_is_written_back_only_while_it_is_exactly_what_the_deletion_left() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join(".env");
    let r = open_root(d.path()).unwrap();
    let original = SecretBytes::copy_from(ORIGINAL);
    let mut edited = LEFT.to_vec();
    edited.extend_from_slice(b"ADDED_LATER=1\n");
    std::fs::write(&p, &edited).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
    let e = restore_over(&r, Path::new(".env"), &original, &sha(LEFT)).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::EditedSince);
    assert!(
        std::fs::read(&p).unwrap() == edited,
        "a file edited after the deletion was written over"
    );
    no_temps(d.path());

    std::fs::write(&p, LEFT).unwrap();
    let before = std::fs::metadata(&p).unwrap();
    let after = restore_over(&r, Path::new(".env"), &original, &sha(LEFT)).unwrap();
    assert!(
        original.ct_eq(&std::fs::read(&p).unwrap()),
        "not byte for byte"
    );
    let now = std::fs::metadata(&p).unwrap();
    assert_eq!(now.mode() & 0o777, 0o640);
    assert_ne!(now.ino(), before.ino(), "a new file was put in its place");
    assert_eq!(after.ino, now.ino());
    no_temps(d.path());
}

/// F-78 (Codex's review): an edit made in place after the last check is
/// kept (`changed`), never written over: the edit has the length of what
/// the deletion left and its modification time is put back, so the file's
/// device, inode, size and modification time are what was checked, and
/// only its contents (and change time) tell. It is made after the last
/// check, before the names are swapped, and through a descriptor held
/// open, after the swap and before what came out is read. A save over
/// the file (another file put under its name) after it was hashed is kept
/// too. Each time the edit keeps the file's name and no temporary file is
/// left.
///
/// Mutation: the write-back without the contents the file must still hold
/// when it comes out of the swap (the old `replace_atomically` path): the
/// in-place edits are written over.
#[test]
fn an_edit_made_while_the_file_is_written_back_is_kept() {
    for when in [Inside::Hashed, Inside::Checked, Inside::Exchanged] {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let p = d.path().join(".env");
        let r = open_root(d.path()).unwrap();
        std::fs::write(&p, LEFT).unwrap();
        let mut edit = LEFT.to_vec();
        let at = edit.len() - 2;
        edit[at] ^= 0x20;
        let mut held: Option<std::fs::File> = None;
        let mut did = false;
        let e = restore_over_observed(
            &r,
            Path::new(".env"),
            &SecretBytes::copy_from(ORIGINAL),
            &sha(LEFT),
            &mut |now| {
                if now == Inside::Hashed {
                    held = Some(std::fs::OpenOptions::new().write(true).open(&p).unwrap());
                }
                if now != when {
                    return;
                }
                if when == Inside::Hashed {
                    // A save: another file put under the name.
                    let saved = d.path().join("saved");
                    std::fs::write(&saved, &edit).unwrap();
                    std::fs::rename(&saved, &p).unwrap();
                } else {
                    let w = held.as_mut().unwrap();
                    let modified = w.metadata().unwrap().modified().unwrap();
                    std::os::unix::fs::FileExt::write_all_at(w, &edit, 0).unwrap();
                    w.set_modified(modified).unwrap();
                }
                did = true;
            },
        )
        .unwrap_err();
        assert!(did, "{when:?}");
        assert_eq!(e.kind, ModifyErrorKind::Changed, "{when:?}");
        assert!(
            std::fs::read(&p).unwrap() == edit,
            "{when:?}: an edit after the last check was written over"
        );
        no_temps(d.path());
    }
}
