//! Different catalog interpretations must not share stale read or omission state.
#![allow(clippy::unwrap_used)]
use envcloak_scan::{
    candidates::Budget,
    scan_config_sources,
    source::{ConfigFormat, ConfigSource, SourceKind},
    transcript::scan_transcript_sources,
};

fn source(path: std::path::PathBuf, format: ConfigFormat, kind: SourceKind) -> ConfigSource {
    ConfigSource {
        path,
        format,
        source_kind: kind,
        label: "fixture".into(),
        names: None,
    }
}

#[test]
fn different_readers_on_one_leaf_preserve_each_interpretation() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let path = d.path().join("store");
    let value = "fixtureZdifferentReader";
    let escaped = value
        .chars()
        .map(|c| format!("\\u{:04x}", c as u32))
        .collect::<String>();
    std::fs::write(&path, format!("{{\"env\":{{\"A\":\"{escaped}\"}}}}")).unwrap();
    let json = source(path.clone(), ConfigFormat::Json, SourceKind::Transcript);
    let raw = source(path.clone(), ConfigFormat::Raw, SourceKind::Transcript);
    let mut found = false;
    let report = scan_transcript_sources(&[raw, json.clone()], Budget::default(), &mut |c| {
        found |= c.value.ct_eq(value.as_bytes());
        true
    })
    .unwrap();
    assert!(report.complete());
    assert!(found, "raw scan suppressed JSON decoding");
    assert_eq!(report.files, 1);

    let yaml = source(path, ConfigFormat::Yaml, SourceKind::McpConfig);
    let report = scan_config_sources(&[yaml, json]).unwrap();
    assert!(!report.complete());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.value.as_ref().is_some_and(|v| v.ct_eq(value.as_bytes())))
    );
    assert_eq!(report.files, 2);
}

#[test]
fn config_and_envfile_readers_do_not_share_parser_results() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let env = d.path().join("values.env");
    std::fs::write(&env, b"A=fixtureZdotenvInterpretation\n").unwrap();
    let config = d.path().join("mcp.json");
    std::fs::write(&config, br#"{"mcpServers":{"s":{"envFile":"values.env"}}}"#).unwrap();
    let report = scan_config_sources(&[
        source(env, ConfigFormat::Yaml, SourceKind::McpConfig),
        source(config, ConfigFormat::Json, SourceKind::McpConfig),
    ])
    .unwrap();
    assert!(!report.complete());
    assert!(report.findings.iter().any(|f| {
        f.value
            .as_ref()
            .is_some_and(|v| v.ct_eq(b"fixtureZdotenvInterpretation"))
    }));
    assert_eq!(report.files, 3);
}

#[test]
fn omissions_cover_overlapping_raw_sources_in_either_order() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::create_dir(d.path().join("credentials")).unwrap();
    std::fs::write(
        d.path().join("credentials/value"),
        b"fixtureZcredentialNotRead",
    )
    .unwrap();
    std::fs::write(d.path().join("state.sqlite"), b"fixtureZdatabaseNotRead").unwrap();
    std::fs::write(d.path().join("run.log"), b"fixtureZeligibleLogValue").unwrap();
    let raw = source(d.path().to_path_buf(), ConfigFormat::Raw, SourceKind::Log);
    let mut database = source(
        d.path().to_path_buf(),
        ConfigFormat::Raw,
        SourceKind::Database,
    );
    database.names = Some(".sqlite".into());
    let credentials = source(
        d.path().join("credentials"),
        ConfigFormat::Json,
        SourceKind::Credentials,
    );
    for sources in [
        [raw.clone(), database.clone(), credentials.clone()],
        [credentials, database, raw],
    ] {
        let mut found = false;
        let mut omitted = false;
        let report = scan_transcript_sources(&sources, Budget::default(), &mut |c| {
            found |= c.value.ct_eq(b"fixtureZeligibleLogValue");
            omitted |= c.value.ct_eq(b"fixtureZcredentialNotRead")
                || c.value.ct_eq(b"fixtureZdatabaseNotRead");
            true
        })
        .unwrap();
        assert!(report.complete());
        assert!(found, "eligible sibling was omitted");
        assert!(!omitted, "omitted store was read");
        assert_eq!(
            report
                .notes
                .iter()
                .filter(|n| n.reason == "database")
                .count(),
            1
        );
        assert_eq!(
            report
                .notes
                .iter()
                .filter(|n| n.reason == "manual_credentials")
                .count(),
            1
        );
    }
}

#[test]
fn envfile_references_cannot_read_a_catalog_omission() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let env = d.path().join("values.env");
    std::fs::write(&env, b"A=fixtureZomittedInclude\n").unwrap();
    let config = d.path().join("mcp.json");
    std::fs::write(&config, br#"{"mcpServers":{"s":{"envFile":"values.env"}}}"#).unwrap();
    let sources = [
        source(config, ConfigFormat::Json, SourceKind::McpConfig),
        source(env, ConfigFormat::Raw, SourceKind::Credentials),
    ];
    let report = scan_config_sources(&sources).unwrap();
    assert!(!report.complete());
    assert!(report.findings.is_empty());
    assert!(report.issues.iter().any(|i| i.reason == "unread_env_file"));
    assert_eq!(report.notes.len(), 1);
}

#[test]
fn empty_catalog_directories_consume_the_file_budget() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let mut sources = Vec::new();
    for n in 0..4 {
        let path = d.path().join(format!("empty{n}"));
        std::fs::create_dir(&path).unwrap();
        sources.push(source(path, ConfigFormat::Raw, SourceKind::Log));
    }
    let path = d.path().join("run.log");
    std::fs::write(&path, b"fixtureZbeyondDirectoryBudget").unwrap();
    sources.push(source(path, ConfigFormat::Raw, SourceKind::Log));
    let mut read = false;
    let report = scan_transcript_sources(
        &sources,
        Budget {
            files: 3,
            ..Budget::default()
        },
        &mut |_| {
            read = true;
            true
        },
    )
    .unwrap();
    assert!(!report.complete());
    assert!(!read);
    assert!(report.issues.iter().any(|i| i.reason == "file_budget"));
}

#[test]
fn overlapping_readers_count_each_physical_occurrence_once() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let path = d.path().join("store");
    let value = b"fixtureZsamePhysicalValue";
    std::fs::write(&path, br#"{"text":"fixtureZsamePhysicalValue"}"#).unwrap();
    for formats in [
        [ConfigFormat::Raw, ConfigFormat::Json],
        [ConfigFormat::Json, ConfigFormat::Raw],
    ] {
        let sources = formats.map(|format| source(path.clone(), format, SourceKind::Transcript));
        for counted in [false, true] {
            let mut candidates = if counted {
                envcloak_scan::candidates::Candidates::counted(Budget::for_counts())
            } else {
                envcloak_scan::candidates::Candidates::new(Budget::default())
            }
            .unwrap();
            let report =
                scan_transcript_sources(&sources, Budget::default(), &mut |c| candidates.insert(c))
                    .unwrap();
            assert!(report.complete());
            assert!(!candidates.limited());
            let found = candidates
                .entries()
                .iter()
                .find(|c| c.value.ct_eq(value))
                .unwrap();
            if counted {
                assert_eq!(found.counts.values().sum::<u64>(), 1);
                assert!(found.occurrences.is_empty());
            } else {
                assert_eq!(found.occurrences.len(), 1);
            }
        }
    }
}

#[test]
fn incompatible_structured_readers_are_visibly_partial() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let path = d.path().join("store");
    std::fs::write(&path, b"{\n\"text\":\"fixtureZstructuredConflict\"\n}\n").unwrap();
    for formats in [
        [ConfigFormat::Json, ConfigFormat::Jsonl],
        [ConfigFormat::Jsonl, ConfigFormat::Json],
    ] {
        let sources = formats.map(|format| source(path.clone(), format, SourceKind::Transcript));
        let report = scan_transcript_sources(&sources, Budget::default(), &mut |_| true).unwrap();
        assert!(!report.complete());
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.reason == "conflicting_formats")
        );
        assert_eq!(report.files, 1);
    }
}
