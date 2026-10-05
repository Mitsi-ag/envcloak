//! Gate 15 for new source kinds, including large streams and name-only leftovers.
#![allow(clippy::unwrap_used)]
use envcloak_scan::{
    candidates::Budget,
    source::{ConfigFormat, ConfigSource, SourceKind},
    transcript::scan_transcript_sources,
};
use std::os::unix::fs::{PermissionsExt, symlink};
fn source(path: std::path::PathBuf) -> ConfigSource {
    ConfigSource {
        path,
        format: ConfigFormat::Mixed,
        source_kind: SourceKind::Transcript,
        label: "fixture".into(),
        names: None,
    }
}
#[test]
fn new_roots_report_fifo_links_unreadable_and_stream_two_gib_within_budget() {
    let d =
        tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).expect("temporary root"))
            .unwrap();
    let store = d.path().join("store");
    std::fs::create_dir(&store).unwrap();
    std::fs::write(store.join("a.txt"), b"fixtureZnormalStreamValue\n").unwrap();
    std::fs::hard_link(store.join("a.txt"), store.join("b.txt")).unwrap();
    symlink(".", store.join("loop")).unwrap();
    let o = std::process::Command::new("/usr/bin/mkfifo")
        .arg(store.join("fifo"))
        .env_clear()
        .output()
        .unwrap();
    assert!(o.status.success());
    std::fs::write(store.join("unreadable"), b"fixtureZunreadableValue").unwrap();
    std::fs::set_permissions(
        store.join("unreadable"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let f = std::fs::File::create(store.join("z-large")).unwrap();
    f.set_len(2 * 1024 * 1024 * 1024).unwrap();
    let mut values = 0;
    let report = scan_transcript_sources(
        &[source(store)],
        Budget {
            bytes: 65536,
            ..Budget::default()
        },
        &mut |c| {
            if c.value.ct_eq(b"fixtureZnormalStreamValue") {
                values += 1;
                assert!(!c.occurrence.rewritable);
            }
            true
        },
    )
    .unwrap();
    assert!(values >= 1);
    assert!(report.bytes <= 65536);
    assert!(!report.complete());
    for reason in [
        "symlink",
        "hard_link",
        "not_regular",
        "unreadable",
        "byte_budget",
    ] {
        assert!(
            report.issues.iter().any(|i| i.reason == reason),
            "missing {reason}"
        );
    }
}
#[test]
fn replaced_directory_is_refused_and_live_file_change_is_not_complete() {
    let d =
        tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).expect("temporary root"))
            .unwrap();
    let store = d.path().join("store");
    let other = d.path().join("other");
    std::fs::create_dir(&store).unwrap();
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("x"), b"fixtureZforeignStreamValue").unwrap();
    let s = source(store.clone());
    std::fs::rename(&store, d.path().join("old")).unwrap();
    symlink(&other, &store).unwrap();
    let report = scan_transcript_sources(&[s], Budget::default(), &mut |_| {
        panic!("followed replaced directory")
    })
    .unwrap();
    assert!(!report.complete());
    assert!(report.issues.iter().any(|i| i.reason == "symlink"));
    let path = other.join("x");
    let mut changed = false;
    let report = scan_transcript_sources(&[source(other)], Budget::default(), &mut |_| {
        if !changed {
            std::fs::write(&path, b"replaced").unwrap();
            changed = true;
        }
        true
    })
    .unwrap();
    assert!(changed);
    assert!(report.issues.iter().any(|i| i.reason == "changed"));
    assert!(!report.complete());
}
#[test]
fn oversized_jsonl_line_is_counted_and_following_line_still_scans() {
    let mut input = vec![b' '; envcloak_scan::transcript::MAX_LINE + 1];
    input.extend_from_slice(b"\n{\"v\":\"fixtureZnextLineToken\"}\n");
    let mut found = false;
    let report = envcloak_scan::transcript::scan_reader(
        &mut std::io::Cursor::new(input),
        ConfigFormat::Jsonl,
        Default::default(),
        Budget::default(),
        &mut |c| {
            found |= c.value.ct_eq(b"fixtureZnextLineToken");
            true
        },
    )
    .unwrap();
    assert!(found);
    assert_eq!(report.not_scanned, 1);
    assert!(!report.complete());
}
