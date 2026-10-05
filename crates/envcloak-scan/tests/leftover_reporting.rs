//! Report-only recovery gates using the actual restore path and owned children.
#![allow(clippy::unwrap_used)]
use envcloak_core::{SecretBytes, file_backup_v2::CHUNK_V2};
use envcloak_scan::{
    BackedUpFile, Inside, ModifyErrorKind, open_root, restore_over_left,
    restore_over_left_observed, scan_config_sources,
    source::{ConfigFormat, ConfigSource, SourceKind},
};
use sha2::{Digest, Sha256};
use std::path::Path;
const LEFT: &[u8] = b"{}\n";
fn record(body: &[u8]) -> BackedUpFile {
    BackedUpFile {
        size: body.len() as u64,
        sha256: Sha256::digest(body).into(),
        sha256_after: Sha256::digest(LEFT).into(),
    }
}
fn source(root: &Path, name: &str) -> ConfigSource {
    ConfigSource {
        path: root.join(name),
        format: ConfigFormat::Json,
        source_kind: SourceKind::McpConfig,
        label: "restore fixture".into(),
        names: None,
    }
}
#[test]
fn interrupted_restore_child() {
    let Some(dir) = std::env::var_os("EC_LEFTOVER_ROOT") else {
        return;
    };
    let name = std::env::var("EC_LEFTOVER_NAME").unwrap();
    let root = open_root(Path::new(&dir)).unwrap();
    let body = vec![b'z'; CHUNK_V2 + 16];
    let _ = restore_over_left(&root, Path::new(&name), &record(&body), &mut |chunk| {
        if chunk == 1 {
            std::process::exit(0);
        }
        Some(SecretBytes::copy_from(&body[..CHUNK_V2]))
    });
    panic!("did not reach the interrupted write");
}
#[test]
fn actual_restore_leftovers_remain_visible_after_refusal_and_other_restore() {
    for name in ["config.json", "transcript.jsonl", ".env"] {
        let d = tempfile::tempdir_in(
            std::fs::canonicalize(std::env::temp_dir()).expect("temporary root"),
        )
        .unwrap();
        let path = d.path().join(name);
        std::fs::write(&path, LEFT).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["interrupted_restore_child", "--exact"])
            .env_clear()
            .env("EC_LEFTOVER_ROOT", d.path())
            .env("EC_LEFTOVER_NAME", name)
            .output()
            .unwrap();
        assert!(child.status.success());
        let s = source(d.path(), name);
        let root = open_root(d.path()).unwrap();
        let check = || {
            let report = scan_config_sources(std::slice::from_ref(&s)).unwrap();
            assert_eq!(report.leftovers.len(), 1);
            assert!(!report.complete());
            assert_eq!(report.leftovers[0].inspection, "possible_leftover");
            report.leftovers[0].source.path.clone()
        };
        let retained = check();
        let other = b"{\"different\":true}\n";
        std::fs::write(&path, b"edited").unwrap();
        assert_eq!(
            restore_over_left(&root, Path::new(name), &record(other), &mut |_| panic!(
                "read on edited_since"
            ))
            .unwrap_err()
            .kind,
            ModifyErrorKind::EditedSince
        );
        assert_eq!(check(), retained);
        std::fs::write(&path, LEFT).unwrap();
        assert!(restore_over_left(&root, Path::new(name), &record(other), &mut |_| None).is_err());
        assert_eq!(check(), retained);
        restore_over_left(&root, Path::new(name), &record(other), &mut |_| {
            Some(SecretBytes::copy_from(other))
        })
        .unwrap();
        assert_eq!(check(), retained);
        assert_eq!(std::fs::metadata(&retained).unwrap().len(), CHUNK_V2 as u64);
    }
}
#[test]
fn displaced_foreign_save_is_reported_without_cleanup() {
    let d =
        tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).expect("temporary root"))
            .unwrap();
    let path = d.path().join("config.json");
    std::fs::write(&path, LEFT).unwrap();
    let root = open_root(d.path()).unwrap();
    let mut held = None;
    let body = b"{\"restored\":true}\n";
    let cs = [envcloak_testkit::Canary::new(
        "RETAINED",
        format!(
            "ecretainZ{:016x}{:016x}",
            envcloak_testkit::fresh_seed(),
            envcloak_testkit::fresh_seed()
        ),
    )];
    let save = cs[0].value();
    let e = restore_over_left_observed(
        &root,
        Path::new("config.json"),
        &record(body),
        &mut |_| Some(SecretBytes::copy_from(body)),
        &mut |point| {
            if point == Inside::Hashed {
                held = Some(std::fs::OpenOptions::new().write(true).open(&path).unwrap());
            }
            if point == Inside::Exchanged {
                let file = held.as_mut().unwrap();
                file.set_len(0).unwrap();
                std::os::unix::fs::FileExt::write_all_at(file, save, 0).unwrap();
                std::fs::rename(&path, d.path().join("away")).unwrap();
            }
        },
    )
    .unwrap_err();
    assert_eq!(e.kind, ModifyErrorKind::MovedAside);
    let report = scan_config_sources(&[source(d.path(), "config.json")]).unwrap();
    assert_eq!(report.leftovers.len(), 1);
    let kept = &report.leftovers[0].source.path;
    assert_eq!(std::fs::read(kept).unwrap(), save);
    assert!(envcloak_testkit::find(format!("{report:?}").as_bytes(), &cs).is_empty());
    assert!(!envcloak_testkit::find(save, &cs).is_empty());
}
