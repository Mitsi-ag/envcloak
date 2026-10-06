//! Gate 15 for new source kinds, including large streams and name-only leftovers.
#![allow(clippy::unwrap_used)]
use envcloak_scan::{
    candidates::Budget,
    source::{ConfigFormat, ConfigSource, SourceKind},
    transcript::scan_transcript_sources,
};
use std::collections::BTreeSet;
use std::os::unix::fs::{FileExt, PermissionsExt, symlink};
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
    // Directory entry order is unspecified. Keep the sparse file in a
    // separate, later source so it cannot spend the readable files' budget.
    // Both sources still share one byte allowance and one report.
    let large = d.path().join("large");
    let f = std::fs::File::create(&large).unwrap();
    f.set_len(2 * 1024 * 1024 * 1024).unwrap();
    f.write_all_at(b"fixtureZlargeStreamValue\n", 0).unwrap();
    f.write_all_at(b"fixtureZpastBudgetValue\n", 65536).unwrap();
    let mut paths = BTreeSet::new();
    let mut streamed = false;
    let report = scan_transcript_sources(
        &[source(store.clone()), source(large.clone())],
        Budget {
            bytes: 65536,
            ..Budget::default()
        },
        &mut |c| {
            if c.value.ct_eq(b"fixtureZnormalStreamValue") {
                paths.insert(c.occurrence.source.path.clone());
                assert!(!c.occurrence.rewritable);
            }
            if c.value.ct_eq(b"fixtureZlargeStreamValue") {
                assert_eq!(c.occurrence.source.path, large);
                streamed = true;
            }
            assert!(!c.value.ct_eq(b"fixtureZpastBudgetValue"));
            assert!(!c.value.ct_eq(b"fixtureZunreadableValue"));
            true
        },
    )
    .unwrap();
    assert_eq!(
        paths,
        BTreeSet::from([store.join("a.txt"), store.join("b.txt")])
    );
    assert!(streamed, "the sparse file's prefix was not scanned");
    assert_eq!(report.bytes, 65536);
    assert!(!report.complete());
    for (path, reason) in [
        (store.join("loop"), "symlink"),
        (store.join("a.txt"), "hard_link"),
        (store.join("b.txt"), "hard_link"),
        (store.join("fifo"), "not_regular"),
        (store.join("unreadable"), "unreadable"),
        (large, "byte_budget"),
    ] {
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.source.path == path && i.reason == reason),
            "missing {reason} for {}",
            path.display()
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

#[test]
fn json_backups_decode_escaped_values_and_report_raw_fallback() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let value = ["fixtureZbackup", "escaped", "value"].join("/");
    let escaped = value
        .bytes()
        .map(|b| format!("\\u{b:04x}"))
        .collect::<String>();
    for (name, input, complete, encoding) in [
        (
            ".claude.json.backup.fixture",
            format!("{{\n  \"text\":\"{escaped}\"\n}}"),
            true,
            envcloak_scan::candidates::Encoding::Json,
        ),
        (
            "valid.json",
            format!("{{\"text\":\"{}\"}}", value.replace('/', "\\/")),
            true,
            envcloak_scan::candidates::Encoding::Json,
        ),
        (
            "broken.json",
            format!("broken {value}"),
            false,
            envcloak_scan::candidates::Encoding::Raw,
        ),
    ] {
        let path = d.path().join(name);
        std::fs::write(&path, &input).unwrap();
        let mut src = source(path);
        src.format = ConfigFormat::Json;
        src.source_kind = SourceKind::HostBackup;
        let mut found = false;
        let report = scan_transcript_sources(&[src], Budget::default(), &mut |c| {
            if c.value.ct_eq(value.as_bytes()) {
                found = true;
                assert_eq!(c.occurrence.encoding, encoding);
                let r = c.occurrence.range;
                if complete {
                    let fragment = &input[r.start as usize..r.end as usize];
                    let decoded: String = serde_json::from_str(&format!("\"{fragment}\"")).unwrap();
                    assert!(decoded == value);
                }
            }
            true
        })
        .unwrap();
        assert_eq!(report.complete(), complete, "{report:?}");
        assert!(found, "backup candidate missing");
        if !complete {
            assert!(report.issues.iter().any(|i| i.reason == "invalid_json"));
        }
    }
}

#[test]
fn whole_json_sources_stop_at_the_document_cap() {
    let limit = envcloak_scan::MAX_DOTENV;
    let report = envcloak_scan::transcript::scan_reader(
        &mut std::io::repeat(b'x'),
        ConfigFormat::Json,
        Default::default(),
        Budget {
            bytes: (limit * 2) as u64,
            ..Budget::default()
        },
        &mut |_| panic!("oversized document emitted"),
    )
    .unwrap();
    assert!(!report.complete());
    assert!(report.issues.iter().any(|i| i.reason == "too_large"));
    assert!(
        report.bytes <= limit as u64 + 1,
        "read beyond the document allowance"
    );
}

#[test]
fn oversized_json_backup_is_refused_before_its_contents_are_read() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let path = d.path().join("backup.json");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(envcloak_scan::MAX_DOTENV as u64 + 1)
        .unwrap();
    let mut src = source(path);
    src.format = ConfigFormat::Json;
    src.source_kind = SourceKind::HostBackup;
    let report = scan_transcript_sources(&[src], Budget::default(), &mut |_| {
        panic!("oversized backup emitted")
    })
    .unwrap();
    assert!(!report.complete());
    assert!(report.issues.iter().any(|i| i.reason == "too_large"));
    assert_eq!(report.bytes, 0);
}
