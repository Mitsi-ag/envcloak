//! Project identity (SPEC §6.1 step 2, gate 28's identity cases): the
//! manifest's directory is canonicalized, opened, and identified by the
//! device and inode of the opened directory together with its canonical
//! path. Copying or moving the repo gives a new identity; a symlinked path
//! to the same directory keeps it. A symlinked manifest is refused.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use envcloak_policy::{
    MANIFEST_NAME, Manifest, ManifestErrorKind, ProjectIdentity, find_manifest, load_project,
    project_identity,
};
use envcloak_testkit::TestHome;
use sha2::{Digest, Sha256};

const MANIFEST: &str =
    "[project]\nname = \"acme-web\"\n\n[env]\nOPENAI_API_KEY = \"openai/work\"\n";

/// `<root>/src/acme-web` with a manifest, canonicalized.
fn repo(home: &TestHome) -> PathBuf {
    let dir = home.root().join("src").join("acme-web");
    std::fs::create_dir_all(dir.join("app").join("deep")).unwrap();
    std::fs::write(dir.join(MANIFEST_NAME), MANIFEST).unwrap();
    std::fs::canonicalize(dir).unwrap()
}

fn id(dir: &Path) -> ProjectIdentity {
    project_identity(&dir.join(MANIFEST_NAME)).unwrap()
}

fn kind(dir: &Path) -> ManifestErrorKind {
    project_identity(&dir.join(MANIFEST_NAME))
        .unwrap_err()
        .kind()
}

fn copy_tree(from: &Path, to: &Path) {
    let st = Command::new("/bin/cp")
        .arg("-R")
        .arg(from)
        .arg(to)
        .status()
        .unwrap();
    assert!(st.success());
}

#[test]
fn identity_is_the_opened_directory() {
    let home = TestHome::new();
    let dir = repo(&home);
    let a = id(&dir);
    let meta = std::fs::metadata(&dir).unwrap();
    assert_eq!(a.canonical_dir, dir);
    assert_eq!((a.dev, a.ino), (meta.dev(), meta.ino()));
    assert_eq!(a.manifest_path, dir.join(MANIFEST_NAME));
    assert_eq!(id(&dir), a);
    assert_eq!(a.vault_key(), id(&dir).vault_key());
    // A path with `.` and `..` in it is the same directory.
    let dotted = dir.join("app").join("..").join(".").join(MANIFEST_NAME);
    assert_eq!(project_identity(&dotted).unwrap(), a);
}

#[test]
fn gate28_copying_the_repo_gives_a_new_identity() {
    let home = TestHome::new();
    let dir = repo(&home);
    let copy = dir.with_file_name("acme-web-copy");
    copy_tree(&dir, &copy);
    let (a, b) = (id(&dir), id(&copy));
    assert_ne!(a, b);
    assert_ne!((a.dev, a.ino), (b.dev, b.ino));
    assert_ne!(a.vault_key(), b.vault_key());
}

#[test]
fn gate28_moving_the_repo_gives_a_new_identity() {
    let home = TestHome::new();
    let dir = repo(&home);
    let before = id(&dir);
    let moved = dir.with_file_name("acme-web-moved");
    std::fs::rename(&dir, &moved).unwrap();
    let after = id(&moved);
    // A rename keeps the inode; the path is part of the identity.
    assert_eq!((before.dev, before.ino), (after.dev, after.ino));
    assert_ne!(before, after);
    assert_ne!(before.vault_key(), after.vault_key());
    // Moving it back restores it.
    std::fs::rename(&moved, &dir).unwrap();
    assert_eq!(id(&dir), before);
    // A new directory at the old path, holding the same manifest, is not
    // the same directory.
    std::fs::rename(&dir, &moved).unwrap();
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join(MANIFEST_NAME), MANIFEST).unwrap();
    let fresh = id(&dir);
    assert_ne!((fresh.dev, fresh.ino), (before.dev, before.ino));
    assert_ne!(fresh, before);
}

/// Review T5 open 4: the vault key holds the device number, so a
/// filesystem that numbers its devices at mount (btrfs subvolumes,
/// removable and external volumes, some network filesystems) gives the
/// same repo a new key after a remount, and it shows as a new project.
/// That is the strict side, kept on purpose: without the device, another
/// filesystem mounted at the same path with a directory of the same inode
/// would inherit the record. The key differs by the device alone; with
/// the path, device and inode the same it is the same key.
#[test]
fn a_new_device_number_is_a_new_project() {
    let at = |dev: u64, ino: u64, dir: &str| ProjectIdentity {
        canonical_dir: PathBuf::from(dir),
        dev,
        ino,
        manifest_path: PathBuf::from(dir).join(MANIFEST_NAME),
    };
    let before = at(0x0801, 4242, "/mnt/work/acme-web");
    assert_eq!(
        before.vault_key(),
        at(0x0801, 4242, "/mnt/work/acme-web").vault_key()
    );
    // Remounted: the same path and inode on a new device number.
    for dev in [0x0802, 0, u64::MAX, 0x0801 << 32] {
        assert_ne!(
            before.vault_key(),
            at(dev, 4242, "/mnt/work/acme-web").vault_key(),
            "{dev:#x}"
        );
    }
    // The inode and the path count too.
    assert_ne!(
        before.vault_key(),
        at(0x0801, 4243, "/mnt/work/acme-web").vault_key()
    );
    assert_ne!(
        before.vault_key(),
        at(0x0801, 4242, "/mnt/work/acme-web2").vault_key()
    );
    // The device and the inode are not interchangeable.
    assert_ne!(at(1, 2, "/x").vault_key(), at(2, 1, "/x").vault_key());
}

#[test]
fn gate28_a_symlinked_path_keeps_the_identity() {
    let home = TestHome::new();
    let dir = repo(&home);
    let a = id(&dir);
    // A symlink to the repo, and one to a directory above it.
    let link = home.root().join("link-to-repo");
    symlink(&dir, &link).unwrap();
    assert_eq!(id(&link), a);
    let up = home.root().join("link-to-src");
    symlink(dir.parent().unwrap(), &up).unwrap();
    assert_eq!(id(&up.join("acme-web")), a);
    // A relative symlink.
    let rel = dir.parent().unwrap().join("rel");
    symlink("acme-web", &rel).unwrap();
    assert_eq!(id(&rel), a);
    assert_eq!(id(&rel).vault_key(), a.vault_key());
}

#[test]
fn gate28_a_case_alias_keeps_the_identity_where_the_filesystem_folds_case() {
    let home = TestHome::new();
    let dir = repo(&home);
    let alias = dir.with_file_name("ACME-WEB");
    if std::fs::symlink_metadata(&alias).is_err() {
        // A case-sensitive filesystem: the alias is another path.
        return;
    }
    // Same directory under another spelling (APFS by default): the
    // canonical path is the stored spelling, so the identity is the same.
    assert_eq!(id(&alias), id(&dir));
    assert_eq!(id(&alias).canonical_dir, dir);
}

#[test]
fn a_symlinked_manifest_is_refused() {
    let home = TestHome::new();
    let dir = repo(&home);
    let real = dir.join("real.toml");
    std::fs::rename(dir.join(MANIFEST_NAME), &real).unwrap();
    // To a file in the same directory, by relative and absolute path.
    symlink("real.toml", dir.join(MANIFEST_NAME)).unwrap();
    assert_eq!(kind(&dir), ManifestErrorKind::SymlinkedManifest);
    std::fs::remove_file(dir.join(MANIFEST_NAME)).unwrap();
    symlink(&real, dir.join(MANIFEST_NAME)).unwrap();
    assert_eq!(kind(&dir), ManifestErrorKind::SymlinkedManifest);
    let e = load_project(&dir.join(MANIFEST_NAME)).unwrap_err();
    assert_eq!(e.kind(), ManifestErrorKind::SymlinkedManifest);
    // A dangling one too.
    std::fs::remove_file(dir.join(MANIFEST_NAME)).unwrap();
    symlink("missing.toml", dir.join(MANIFEST_NAME)).unwrap();
    assert_eq!(kind(&dir), ManifestErrorKind::SymlinkedManifest);
    // `find_manifest` still reports it, so the refusal is seen rather than
    // a manifest further up being used in its place.
    std::fs::write(dir.parent().unwrap().join(MANIFEST_NAME), MANIFEST).unwrap();
    assert_eq!(
        find_manifest(&dir.join("app")).unwrap(),
        Some(dir.join(MANIFEST_NAME))
    );
}

#[test]
fn only_a_regular_file_named_envcloak_toml_is_a_manifest() {
    let home = TestHome::new();
    let dir = repo(&home);
    std::fs::remove_file(dir.join(MANIFEST_NAME)).unwrap();
    assert_eq!(kind(&dir), ManifestErrorKind::NotFound);

    std::fs::create_dir(dir.join(MANIFEST_NAME)).unwrap();
    assert_eq!(kind(&dir), ManifestErrorKind::NotRegularFile);
    std::fs::remove_dir(dir.join(MANIFEST_NAME)).unwrap();

    // A FIFO neither hangs the open nor passes.
    let st = Command::new("/usr/bin/mkfifo")
        .arg(dir.join(MANIFEST_NAME))
        .status()
        .unwrap();
    assert!(st.success());
    let (tx, rx) = mpsc::channel();
    let m = dir.join(MANIFEST_NAME);
    std::thread::spawn(move || {
        let _ = tx.send(load_project(&m).map(drop).map_err(|e| e.kind()));
    });
    let got = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("opening a FIFO hung");
    assert_eq!(got, Err(ManifestErrorKind::NotRegularFile));
    std::fs::remove_file(dir.join(MANIFEST_NAME)).unwrap();
    std::fs::write(dir.join(MANIFEST_NAME), MANIFEST).unwrap();

    for bad in [
        PathBuf::from("envcloak.toml"),
        PathBuf::from("src/envcloak.toml"),
        dir.join("other.toml"),
        dir.join("envcloak.toml.bak"),
        dir.clone(),
        PathBuf::from("/"),
    ] {
        let e = project_identity(&bad).unwrap_err();
        assert_eq!(
            e.kind(),
            ManifestErrorKind::InvalidPath,
            "{}",
            bad.display()
        );
    }
    let e = project_identity(&dir.join("nowhere").join(MANIFEST_NAME)).unwrap_err();
    assert_eq!(e.kind(), ManifestErrorKind::NotFound);
}

#[test]
fn load_project_parses_the_file_it_opened() {
    let home = TestHome::new();
    let dir = repo(&home);
    let p = load_project(&dir.join(MANIFEST_NAME)).unwrap();
    assert_eq!(p.identity, id(&dir));
    assert_eq!(p.manifest.project_name.as_deref(), Some("acme-web"));
    assert_eq!(
        p.manifest.sha256,
        <[u8; 32]>::from(Sha256::digest(MANIFEST))
    );

    // Through a symlinked directory: the same project and manifest.
    let link = home.root().join("l");
    symlink(&dir, &link).unwrap();
    let q = load_project(&link.join(MANIFEST_NAME)).unwrap();
    assert_eq!(q.identity, p.identity);
    assert_eq!(q.manifest, p.manifest);

    // Over the size cap, whatever it holds.
    let big = format!("{MANIFEST}{}", "#".repeat(Manifest::MAX_LEN));
    std::fs::write(dir.join(MANIFEST_NAME), big).unwrap();
    let e = load_project(&dir.join(MANIFEST_NAME)).unwrap_err();
    assert_eq!(e.kind(), ManifestErrorKind::TooLarge);
    // A parse error comes back with its line.
    std::fs::write(dir.join(MANIFEST_NAME), "[env]\nA = \"a/b\"\nB = 1\n").unwrap();
    let e = load_project(&dir.join(MANIFEST_NAME)).unwrap_err();
    assert_eq!(e.kind(), ManifestErrorKind::WrongType);
    assert_eq!(
        e.origin(),
        Some(envcloak_policy::Origin::Manifest { line: 3 })
    );
}

#[test]
fn find_manifest_walks_up_to_the_nearest() {
    let home = TestHome::new();
    let dir = repo(&home);
    let deep = dir.join("app").join("deep");
    assert_eq!(find_manifest(&deep).unwrap(), Some(dir.join(MANIFEST_NAME)));
    assert_eq!(find_manifest(&dir).unwrap(), Some(dir.join(MANIFEST_NAME)));
    // The nearest wins.
    std::fs::write(dir.join("app").join(MANIFEST_NAME), MANIFEST).unwrap();
    assert_eq!(
        find_manifest(&deep).unwrap(),
        Some(dir.join("app").join(MANIFEST_NAME))
    );
    // A start below a symlink walks the directories the kernel sees.
    let link = home.root().join("deep-link");
    symlink(&deep, &link).unwrap();
    assert_eq!(
        find_manifest(&link).unwrap(),
        Some(dir.join("app").join(MANIFEST_NAME))
    );
    // A file as the start: its directory and up.
    let file = deep.join("main.rs");
    std::fs::write(&file, "fn main() {}\n").unwrap();
    assert_eq!(
        find_manifest(&file).unwrap(),
        Some(dir.join("app").join(MANIFEST_NAME))
    );
    // Nothing above the test home (the manifests in it are removed).
    std::fs::remove_file(dir.join("app").join(MANIFEST_NAME)).unwrap();
    std::fs::remove_file(dir.join(MANIFEST_NAME)).unwrap();
    let above = find_manifest(&deep).unwrap();
    assert!(
        above
            .as_deref()
            .is_none_or(|p| !p.starts_with(home.root().canonicalize().unwrap())),
        "{above:?}"
    );
    assert!(find_manifest(&home.root().join("missing")).is_err());
}

#[test]
fn find_manifest_stops_where_it_cannot_look() {
    if envcloak_sys::effective_uid() == 0 {
        // Permission bits do not stop root.
        return;
    }
    let home = TestHome::new();
    let dir = repo(&home);
    let deep = dir.join("app").join("deep");
    // `deep` cannot be searched, so whether it holds a manifest is unknown:
    // the walk fails rather than going on to the repo's.
    std::fs::set_permissions(&deep, std::fs::Permissions::from_mode(0o600)).unwrap();
    let got = find_manifest(&deep);
    std::fs::set_permissions(&deep, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        got.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(find_manifest(&deep).unwrap(), Some(dir.join(MANIFEST_NAME)));
}
