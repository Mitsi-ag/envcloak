//! Included config files keep the same refusal and accounting rules.
#![allow(clippy::unwrap_used)]
use envcloak_scan::{
    agent_config::scan_config_sources_with_budget,
    candidates::Budget,
    source::{ConfigFormat, ConfigSource, SourceKind},
};
fn source(path: std::path::PathBuf) -> ConfigSource {
    ConfigSource {
        path,
        format: ConfigFormat::Json,
        source_kind: SourceKind::McpConfig,
        label: "fixture".into(),
        names: None,
    }
}
#[test]
fn envfile_templates_links_and_limits_remain_visible() {
    let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let template = d.path().join("template.json");
    std::fs::write(
        &template,
        br#"{"mcpServers":{"fixture":{"envFile":"${FILE}"}}}"#,
    )
    .unwrap();
    let report = scan_config_sources_with_budget(&[source(template)], Budget::default()).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.name.ct_eq(b"envFile") && f.value.is_none())
    );
    std::fs::write(d.path().join("values.env"), b"NAME=fixture-value\n").unwrap();
    std::fs::hard_link(d.path().join("values.env"), d.path().join("other.env")).unwrap();
    let one = d.path().join("one.json");
    let two = d.path().join("two.json");
    for path in [&one, &two] {
        std::fs::write(
            path,
            br#"{"mcpServers":{"fixture":{"envFile":"values.env"}}}"#,
        )
        .unwrap();
    }
    let report =
        scan_config_sources_with_budget(&[source(one.clone())], Budget::default()).unwrap();
    assert!(report.issues.iter().any(|i| i.reason == "hard_link"));
    let report = scan_config_sources_with_budget(
        &[source(one), source(two)],
        Budget {
            files: 2,
            ..Budget::default()
        },
    )
    .unwrap();
    assert!(report.files <= 2);
    assert!(report.issues.iter().any(|i| i.reason == "file_budget"));
}
