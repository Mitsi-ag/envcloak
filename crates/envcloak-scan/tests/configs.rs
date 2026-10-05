//! M2-12 config, approved-root and report-only recovery gates.
#![allow(clippy::unwrap_used)]
use envcloak_core::SecretBytes;
use envcloak_scan::{
    agent_config::{parse_config, scan_config_sources},
    source::{ConfigFormat, ConfigSource, SourceKind},
};
fn dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ec-c")
        .tempdir_in(std::fs::canonicalize(std::env::temp_dir()).expect("temporary root"))
        .unwrap()
}
fn source(path: std::path::PathBuf, format: ConfigFormat) -> ConfigSource {
    ConfigSource {
        path,
        format,
        source_kind: SourceKind::McpConfig,
        label: "fixture".into(),
        names: None,
    }
}
#[test]
fn config_slots_templates_and_envfile_are_found() {
    let d = dir();
    let p = d.path().join("mcp.json");
    std::fs::write(&p,br#"{"mcpServers":{"fixture":{"env":{"A":"literal","B":"${VAR}"},"headers":{"Authorization":"literal-header"},"auth":{"CLIENT_SECRET":"literal-auth"},"envFile":"fixture.env"}}}"#).unwrap();
    std::fs::write(d.path().join("fixture.env"), b"C=fixture-env\n").unwrap();
    let report = scan_config_sources(&[source(p, ConfigFormat::Json)]).unwrap();
    assert!(report.complete(), "{:?}", report.issues);
    assert_eq!(report.findings.len(), 5);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.value.is_none() && f.name.ct_eq(b"B"))
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.value.as_ref().is_some_and(|v| v.ct_eq(b"fixture-env")))
    );
    let toml=SecretBytes::copy_from(b"[mcp_servers.fixture.env]\nA='literal'\n[mcp_servers.fixture.http_headers]\nAuthorization='header'\n");
    let report = parse_config(&toml, ConfigFormat::Toml);
    assert!(report.complete());
    assert_eq!(report.findings.len(), 2);
    let bad = parse_config(
        &SecretBytes::copy_from(b"[mcp_servers\n"),
        ConfigFormat::Toml,
    );
    assert!(!bad.complete());
    assert!(!parse_config(&SecretBytes::copy_from(b"x: y"), ConfigFormat::Yaml).complete());
}
#[test]
fn leftovers_are_ambiguous_metadata_only_and_never_removed() {
    use std::os::unix::fs::symlink;
    let d = dir();
    let p = d.path().join("config.json");
    std::fs::write(&p, b"{}").unwrap();
    for kind in ["new", "swap"] {
        std::fs::write(
            d.path()
                .join(format!(".config.json.envcloak-{kind}-01234567.tmp")),
            b"foreign-fixture-contents",
        )
        .unwrap();
    }
    std::fs::write(
        d.path().join(".config.json.envcloak-new-nothex.tmp"),
        b"near miss",
    )
    .unwrap();
    symlink(
        "config.json",
        d.path().join(".config.json.envcloak-new-abcdef01.tmp"),
    )
    .unwrap();
    let report = scan_config_sources(&[source(p, ConfigFormat::Json)]).unwrap();
    assert_eq!(report.leftovers.len(), 3);
    assert!(report.leftovers.iter().any(|l| l.inspection == "symlink"));
    assert!(
        report
            .leftovers
            .iter()
            .filter(|l| l.inspection == "possible_leftover")
            .count()
            == 2
    );
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 5);
    assert!(!format!("{report:?}").contains("foreign-fixture-contents"));
}
#[test]
fn config_links_and_unsupported_stores_are_visible() {
    use std::os::unix::fs::symlink;
    let d = dir();
    std::fs::write(d.path().join("target"), b"{}").unwrap();
    symlink("target", d.path().join("linked")).unwrap();
    let mut db = source(d.path().join("state.sqlite"), ConfigFormat::Raw);
    db.source_kind = SourceKind::Database;
    let report =
        scan_config_sources(&[source(d.path().join("linked"), ConfigFormat::Json), db]).unwrap();
    assert!(report.issues.iter().any(|i| i.reason == "symlink"));
    assert!(report.issues.iter().any(|i| i.reason == "database"));
    assert!(!report.complete());
}
