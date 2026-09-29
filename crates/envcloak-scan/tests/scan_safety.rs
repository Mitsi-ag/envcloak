//! Gate 15 (SPEC §15.2), on the scanner: a symlinked `.env` outside the
//! root, a FIFO, a 2 GB file, a directory symlink loop, a hard link and an
//! unreadable file. Expected: no hang, nothing followed or modified, and
//! no value in what the scan reports. The CLI's own test
//! (`crates/envcloak-cli/tests/import.rs`) runs the same tree through
//! `envcloak import` and `envcloak init`.
#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, SystemTime};

use envcloak_scan::{
    FileKind, FileStamp, MAX_DOTENV, ModifyErrorKind, ScanErrorKind, WalkOptions, open_root,
    read_capped, remove_checked, replace_atomically, walk_dotenv,
};
use envcloak_testkit::{Canary, assert_no_canary, by_label, canaries, fresh_seed, labels};

/// Runs `f` on another thread and fails the test if it does not finish
/// within `limit`: a scan that hangs on a FIFO or loops on a symlink never
/// returns.
fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).expect("the scan hung")
}

struct Tree {
    _dir: tempfile::TempDir,
    root: PathBuf,
    outside: PathBuf,
    cs: Vec<Canary>,
}

/// Snapshot of a file that must not change: its bytes (a symlink's
/// target; nothing of a FIFO or a large file, which are not read), size,
/// mode, link count and modification time.
fn snapshot(p: &Path) -> (Vec<u8>, u64, u32, u64, i64, i64) {
    let m = std::fs::symlink_metadata(p).unwrap();
    let bytes = if m.file_type().is_symlink() {
        std::fs::read_link(p)
            .unwrap()
            .into_os_string()
            .into_encoded_bytes()
    } else if m.file_type().is_file() && m.len() <= 1 << 20 {
        std::fs::read(p).unwrap_or_default()
    } else {
        Vec::new()
    };
    (
        bytes,
        m.len(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
    )
}

/// The tree of gate 15. `root/` holds:
/// - `.env`: a symlink to `outside/real.env`, which holds a canary;
/// - `.env.fifo`: a FIFO;
/// - `.env.big`: a sparse 2 GB file;
/// - `loop/self`, a symlink to `..`, and `spin`, a symlink to itself;
/// - `.env.linked`: a hard link to `outside/linked.env`, holding a canary;
/// - `.env.locked`: a file no one may read;
/// - `app/.env`: an ordinary file, which a recursive walk finds.
fn tree() -> Tree {
    let dir = tempfile::Builder::new()
        .prefix("ecs")
        .tempdir_in("/tmp")
        .unwrap();
    let root = dir.path().join("root");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(root.join("app")).unwrap();
    std::fs::create_dir_all(root.join("loop")).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let cs = canaries(fresh_seed());
    let key = by_label(&cs, labels::OPENAI_API_KEY).as_str();
    let token = by_label(&cs, labels::GITHUB_TOKEN).as_str();
    let stripe = by_label(&cs, labels::STRIPE_SECRET_KEY).as_str();
    std::fs::write(outside.join("real.env"), format!("OPENAI_API_KEY={key}\n")).unwrap();
    symlink(outside.join("real.env"), root.join(".env")).unwrap();
    let st = Command::new("/usr/bin/mkfifo")
        .arg(root.join(".env.fifo"))
        .status()
        .unwrap();
    assert!(st.success());
    let big = File::create(root.join(".env.big")).unwrap();
    big.set_len(2 * 1024 * 1024 * 1024).unwrap();
    symlink("..", root.join("loop").join("self")).unwrap();
    symlink("spin", root.join("spin")).unwrap();
    std::fs::write(
        outside.join("linked.env"),
        format!("GITHUB_TOKEN={token}\n"),
    )
    .unwrap();
    std::fs::hard_link(outside.join("linked.env"), root.join(".env.linked")).unwrap();
    let mut locked = File::create(root.join(".env.locked")).unwrap();
    locked
        .write_all(format!("STRIPE_SECRET_KEY={stripe}\n").as_bytes())
        .unwrap();
    locked
        .set_permissions(std::fs::Permissions::from_mode(0o000))
        .unwrap();
    std::fs::write(root.join("app").join(".env"), b"PORT=8080\n").unwrap();
    Tree {
        _dir: dir,
        root,
        outside,
        cs,
    }
}

/// Every path in the tree whose bytes, mode or links must stay as they
/// are.
fn watched(t: &Tree) -> Vec<PathBuf> {
    vec![
        t.outside.join("real.env"),
        t.outside.join("linked.env"),
        t.root.join(".env"),
        t.root.join(".env.linked"),
        t.root.join(".env.big"),
        t.root.join(".env.fifo"),
        t.root.join("loop").join("self"),
        t.root.join("spin"),
    ]
}

fn running_as_root() -> bool {
    envcloak_sys::effective_uid() == 0
}

#[test]
fn gate_15_the_walk_ends_follows_nothing_and_reports_no_value() {
    let t = tree();
    let before: Vec<_> = watched(&t).iter().map(|p| snapshot(p)).collect();
    let root = t.root.clone();
    let results = within(Duration::from_secs(20), move || {
        let r = open_root(&root).unwrap();
        let o = WalkOptions {
            recursive: true,
            ..WalkOptions::default()
        };
        walk_dotenv(&r, &o).collect::<Vec<_>>()
    });
    let mut found = Vec::new();
    let mut skipped = Vec::new();
    for r in &results {
        match r {
            Ok(f) => found.push((f.rel.to_string_lossy().into_owned(), f.hard_linked)),
            Err(e) => skipped.push((e.rel.to_string_lossy().into_owned(), e.kind)),
        }
    }
    found.sort();
    skipped.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        found,
        [
            (".env.linked".to_owned(), true),
            ("app/.env".to_owned(), false)
        ]
    );
    let mut want = vec![
        (".env".to_owned(), ScanErrorKind::Symlink),
        (".env.big".to_owned(), ScanErrorKind::TooLarge),
        (".env.fifo".to_owned(), ScanErrorKind::NotRegular),
    ];
    if !running_as_root() {
        want.push((".env.locked".to_owned(), ScanErrorKind::Unreadable));
    }
    assert_eq!(skipped, want);
    // The report names paths and fixed reasons, never a value.
    let report = format!("{results:?}");
    assert_no_canary(report.as_bytes(), &t.cs);
    for r in &results {
        if let Err(e) = r {
            assert_no_canary(e.to_string().as_bytes(), &t.cs);
        }
    }
    let after: Vec<_> = watched(&t).iter().map(|p| snapshot(p)).collect();
    assert_eq!(before, after, "the scan changed a file");
}

#[test]
fn gate_15_reads_refuse_without_hanging_or_following() {
    let t = tree();
    let before: Vec<_> = watched(&t).iter().map(|p| snapshot(p)).collect();
    let root = t.root.clone();
    let got = within(Duration::from_secs(20), move || {
        let r = open_root(&root).unwrap();
        [
            ".env",
            ".env.fifo",
            ".env.big",
            ".env.locked",
            "spin",
            "loop/self/.env",
        ]
        .map(|p| read_capped(&r, Path::new(p), MAX_DOTENV).map(|(v, _)| v.len()))
    });
    let kinds: Vec<_> = got
        .iter()
        .map(|r| r.as_ref().map_err(|e| e.kind).err())
        .collect();
    assert_eq!(kinds[0], Some(ScanErrorKind::Symlink));
    assert_eq!(kinds[1], Some(ScanErrorKind::NotRegular));
    assert_eq!(kinds[2], Some(ScanErrorKind::TooLarge));
    if !running_as_root() {
        assert_eq!(kinds[3], Some(ScanErrorKind::Unreadable));
    }
    assert_eq!(kinds[4], Some(ScanErrorKind::Symlink));
    // A path through a directory symlink is never followed.
    assert_eq!(kinds[5], Some(ScanErrorKind::Symlink));

    // A hard link is read (it is this user's file), and reported as linked.
    let r = open_root(&t.root).unwrap();
    let (bytes, stamp) = read_capped(&r, Path::new(".env.linked"), MAX_DOTENV).unwrap();
    assert!(!bytes.is_empty());
    assert_eq!(stamp.nlink, 2);
    let after: Vec<_> = watched(&t).iter().map(|p| snapshot(p)).collect();
    assert_eq!(before, after, "a read changed a file");
}

#[test]
fn gate_15_nothing_in_the_tree_is_modified_or_removed() {
    let t = tree();
    // Old enough that only the other rules can refuse.
    let old = SystemTime::now() - Duration::from_secs(3600);
    for p in [
        t.outside.join("real.env"),
        t.outside.join("linked.env"),
        t.root.join(".env.big"),
    ] {
        File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(old)
            .unwrap();
    }
    let before: Vec<_> = watched(&t).iter().map(|p| snapshot(p)).collect();
    let r = open_root(&t.root).unwrap();
    // A stamp that matches the hard link exactly: only the link refuses.
    let linked = FileStamp::of(&std::fs::metadata(t.root.join(".env.linked")).unwrap());
    let e = remove_checked(&r, Path::new(".env.linked"), &linked).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::HardLinked);
    let e = replace_atomically(&r, Path::new(".env.linked"), b"X=1\n", &linked).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::HardLinked);
    // The symlink is refused whatever stamp is offered, even its target's.
    let target = FileStamp::of(&std::fs::metadata(t.outside.join("real.env")).unwrap());
    let e = remove_checked(&r, Path::new(".env"), &target).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Scan(ScanErrorKind::Symlink));
    let e = replace_atomically(&r, Path::new(".env"), b"X=1\n", &target).unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::Scan(ScanErrorKind::Symlink));
    // The FIFO and the big file are refused as what they are.
    let big = FileStamp::of(&std::fs::metadata(t.root.join(".env.big")).unwrap());
    let fifo = within(Duration::from_secs(20), {
        let root = t.root.clone();
        move || {
            let r = open_root(&root).unwrap();
            remove_checked(&r, Path::new(".env.fifo"), &big)
                .unwrap_err()
                .kind
        }
    });
    assert_eq!(fifo, ModifyErrorKind::Scan(ScanErrorKind::NotRegular));
    let after: Vec<_> = watched(&t).iter().map(|p| snapshot(p)).collect();
    assert_eq!(before, after, "a refused change changed a file");
    // No temporary file was left beside any of them.
    for d in [&t.root, &t.outside] {
        for e in std::fs::read_dir(d).unwrap() {
            let n = e.unwrap().file_name();
            assert!(!n.to_string_lossy().contains("envcloak"), "{n:?}");
        }
    }
}

#[test]
fn template_files_and_profiles_are_told_apart() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    for name in [
        ".env",
        ".env.production",
        ".env.Development.Local",
        ".env.example",
        ".env.SAMPLE",
        ".env.template",
        ".env.dist",
        ".env.",
        ".env.bad name",
        ".envrc",
        "x.env",
    ] {
        std::fs::write(dir.path().join(name), b"A=1\n").unwrap();
    }
    let r = open_root(dir.path()).unwrap();
    let mut got: Vec<(String, Result<FileKind, ScanErrorKind>)> =
        walk_dotenv(&r, &WalkOptions::default())
            .map(|x| match x {
                Ok(f) => (f.rel.to_string_lossy().into_owned(), Ok(f.kind)),
                Err(e) => (e.rel.to_string_lossy().into_owned(), Err(e.kind)),
            })
            .collect();
    got.sort_by(|a, b| a.0.cmp(&b.0));
    let profile = |p: &str| {
        Ok(FileKind::Dotenv {
            profile: Some(envcloak_policy::ProfileName::new(p).unwrap()),
        })
    };
    assert_eq!(
        got,
        vec![
            (".env".to_owned(), Ok(FileKind::Dotenv { profile: None })),
            (".env.".to_owned(), Err(ScanErrorKind::ProfileName)),
            (
                ".env.Development.Local".to_owned(),
                profile("development-local")
            ),
            (".env.SAMPLE".to_owned(), Ok(FileKind::Template)),
            (".env.bad name".to_owned(), Err(ScanErrorKind::ProfileName)),
            (".env.dist".to_owned(), Ok(FileKind::Template)),
            (".env.example".to_owned(), Ok(FileKind::Template)),
            (".env.production".to_owned(), profile("production")),
            (".env.template".to_owned(), Ok(FileKind::Template)),
        ]
    );
}

#[test]
fn a_walk_skips_dependency_and_cache_directories_and_stops_at_depth() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    for d in ["node_modules/pkg", ".git", "a/b/c/d", "keep"] {
        std::fs::create_dir_all(dir.path().join(d)).unwrap();
    }
    for f in [
        "node_modules/pkg/.env",
        ".git/.env",
        "a/b/c/d/.env",
        "keep/.env",
    ] {
        std::fs::write(dir.path().join(f), b"A=1\n").unwrap();
    }
    let r = open_root(dir.path()).unwrap();
    let o = WalkOptions {
        recursive: true,
        max_depth: 3,
        ..WalkOptions::default()
    };
    let got: Vec<_> = walk_dotenv(&r, &o)
        .map(|x| match x {
            Ok(f) => (f.rel.to_string_lossy().into_owned(), None),
            Err(e) => (e.rel.to_string_lossy().into_owned(), Some(e.kind)),
        })
        .collect();
    assert_eq!(
        got,
        [
            ("a/b/c/d".to_owned(), Some(ScanErrorKind::TooDeep)),
            ("keep/.env".to_owned(), None),
        ]
    );
    // Without `recursive`, only the root is listed.
    assert_eq!(walk_dotenv(&r, &WalkOptions::default()).count(), 0);
}

/// The environment variable that makes
/// [`a_walk_over_many_sibling_projects_keeps_few_descriptors_open`] run its
/// child half, over the tree it names.
const MANY_DIRS: &str = "ENVCLOAK_T13_MANY_DIRS";
/// Sibling projects in that tree, each with a `.env` and a subdirectory.
const SIBLINGS: usize = 300;

/// `envcloak import --scan ~/Dev` over hundreds of repos: the walk keeps
/// only its path open, so a process allowed 64 descriptors (macOS allows
/// 256 by default) finds every project's file. The child half runs this
/// test binary again under `ulimit -n 64`.
#[test]
fn a_walk_over_many_sibling_projects_keeps_few_descriptors_open() {
    if let Some(root) = std::env::var_os(MANY_DIRS) {
        // The limit is in force: holding 64 more descriptors fails.
        let r = open_root(Path::new(&root)).unwrap();
        let held: Vec<_> = (0..64).map(|_| r.dir().try_clone()).collect();
        assert!(
            held.iter().any(|h| h
                .as_ref()
                .is_err_and(|e| e.raw_os_error() == Some(libc::EMFILE))),
            "the descriptor limit is not in force"
        );
        drop(held);
        let o = WalkOptions {
            recursive: true,
            ..WalkOptions::default()
        };
        let mut found = 0;
        let mut failed = Vec::new();
        for x in walk_dotenv(&r, &o) {
            match x {
                Ok(_) => found += 1,
                Err(e) => failed.push(e),
            }
        }
        assert!(
            failed.is_empty(),
            "{} not read, the first {:?}",
            failed.len(),
            failed.first()
        );
        assert_eq!(found, SIBLINGS);
        println!("walked {found}");
        return;
    }
    let dir = tempfile::Builder::new()
        .prefix("ecw")
        .tempdir_in("/tmp")
        .unwrap();
    for i in 0..SIBLINGS {
        let p = dir.path().join(format!("repo-{i:03}"));
        std::fs::create_dir_all(p.join("src")).unwrap();
        std::fs::write(p.join(".env"), b"# names only\n").unwrap();
    }
    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg("ulimit -n 64 && exec \"$0\" \"$@\"")
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_walk_over_many_sibling_projects_keeps_few_descriptors_open",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(MANY_DIRS, dir.path())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains(&format!("walked {SIBLINGS}")), "{text}");
}
