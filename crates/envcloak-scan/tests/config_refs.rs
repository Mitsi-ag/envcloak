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

#[test]
fn selection_never_removes_omission_policy_from_overlapping_sources() {
    for kind in [SourceKind::Credentials, SourceKind::Database] {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let protected = home.path().join("protected.json");
        std::fs::write(
            &protected,
            br#"{"mcpServers":{"fixture":{"env":{"SECRET_TOKEN":"fixture value"}}}}"#,
        )
        .unwrap();
        let mut broad = source(home.path().to_path_buf());
        broad.names = Some(".json".into());
        let mut omitted = source(protected.clone());
        omitted.source_kind = kind;
        let report = envcloak_scan::agent_config::scan_config_sources_selected(
            &[broad, omitted],
            Budget::default(),
            &|path| path != protected,
        )
        .unwrap();
        assert!(report.findings.is_empty(), "selection removed an omission");
        assert_eq!(report.files, 0);
        assert!(
            report
                .notes
                .iter()
                .any(|n| matches!(n.reason, "manual_credentials" | "database"))
        );
    }
}

#[test]
fn credential_store_case_aliases_are_conservatively_omitted() {
    for directory in [false, true] {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let name = if directory {
            "MCP-SECRETS/values"
        } else {
            "AUTH.JSON"
        };
        let target = home.path().join(name);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, b"SECRET_TOKEN=fixture value\n").unwrap();
        let config = home.path().join("config.json");
        std::fs::write(
            &config,
            format!(r#"{{"mcpServers":{{"fixture":{{"envFile":"{name}"}}}}}}"#),
        )
        .unwrap();
        let mut omitted = source(home.path().join(if directory {
            "mcp-secrets"
        } else {
            "auth.json"
        }));
        omitted.source_kind = SourceKind::Credentials;
        let report = envcloak_scan::scan_config_sources(&[source(config), omitted]).unwrap();
        assert!(
            report.findings.is_empty(),
            "case alias read a protected store"
        );
        assert!(report.issues.iter().any(|i| i.reason == "unread_env_file"));
        assert_eq!(report.files, 1);
    }
}
