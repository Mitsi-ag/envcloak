//! Config grammar, schema coverage and bounded accumulation regressions.
#![allow(clippy::unwrap_used)]
use envcloak_core::SecretBytes;
use envcloak_scan::{
    agent_config::{parse_config, scan_config_sources_with_budget},
    candidates::{Budget, Disposition},
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
fn dir() -> tempfile::TempDir {
    tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
}
#[test]
fn config_reference_grammar_is_explicit() {
    for (value, disposition) in [
        ("cost$5", Disposition::Literal),
        ("$PLAIN", Disposition::Literal),
        ("${NAME}", Disposition::Template),
        ("prefix${NAME:-fallback}", Disposition::Template),
        ("envcloak://item/fixture", Disposition::Template),
        ("${env:NAME}", Disposition::Manual),
        ("${BROKEN", Disposition::Manual),
        ("${}", Disposition::Manual),
        ("${NAME:+other}", Disposition::Manual),
    ] {
        for format in [ConfigFormat::Json, ConfigFormat::Toml] {
            let text = match format {
                ConfigFormat::Json => format!(
                    "{{\"mcpServers\":{{\"s\":{{\"env\":{{\"A\":{}}}}}}}}}",
                    serde_json::to_string(value).unwrap()
                ),
                _ => format!("[mcp_servers.s.env]\nA='{value}'\n"),
            };
            let r = parse_config(&SecretBytes::from_vec(text.into_bytes()), format);
            assert_eq!(r.findings.len(), 1);
            assert_eq!(r.findings[0].disposition, disposition);
            assert_eq!(r.complete(), disposition != Disposition::Manual);
            assert_eq!(
                r.findings[0].value.is_some(),
                disposition == Disposition::Literal
            );
        }
    }
}
#[test]
fn settings_servers_and_toml_arguments_are_read() {
    for (text, format, count) in [
        (r#"{"env":{"A":"fixture"}}"#, ConfigFormat::Json, 1),
        (
            r#"{"servers":{"s":{"env":{"A":"fixture"},"headers":{"B":"fixture"},"envFile":"a.env","args":["fixture"]}}}"#,
            ConfigFormat::Json,
            4,
        ),
        ("[mcp_servers.s]\nargs=['fixture']\n", ConfigFormat::Toml, 1),
    ] {
        let r = parse_config(&SecretBytes::copy_from(text.as_bytes()), format);
        assert!(r.complete());
        assert_eq!(r.findings.len(), count);
        for f in &r.findings {
            assert!(f.value.is_some());
            if f.name.ct_eq(b"args") {
                assert_eq!(f.disposition, Disposition::Manual);
            }
        }
    }
}
#[test]
fn recognized_malformed_bindings_are_incomplete() {
    for text in [
        r#"{"servers":{"s":7}}"#,
        r#"{"env":7}"#,
        r#"{"apiKey":7}"#,
        r#"{"mcpServers":{"s":{"args":7}}}"#,
        r#"{"mcpServers":{"s":{"args":[7]}}}"#,
    ] {
        assert!(
            !parse_config(&SecretBytes::copy_from(text.as_bytes()), ConfigFormat::Json).complete()
        );
    }
    for text in [
        "[mcp_servers]\ns=7",
        "[mcp_servers.s]\nargs=7",
        "[mcp_servers.s]\nargs=[7]",
        "[mcp_servers.s.env]\nA=7",
    ] {
        assert!(
            !parse_config(&SecretBytes::copy_from(text.as_bytes()), ConfigFormat::Toml).complete()
        );
    }
}
#[test]
fn included_template_files_and_unread_references_are_visible() {
    let d = dir();
    let config = d.path().join("config.json");
    for suffix in ["example", "sample", "template", "dist"] {
        let name = format!(".env.{suffix}");
        std::fs::write(d.path().join(&name), b"A=fixture\n").unwrap();
        std::fs::write(
            &config,
            format!("{{\"servers\":{{\"s\":{{\"envFile\":\"{name}\"}}}}}}"),
        )
        .unwrap();
        let r =
            scan_config_sources_with_budget(&[source(config.clone())], Budget::default()).unwrap();
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        assert!(r.findings[0].value.is_none());
        assert_eq!(r.findings[0].disposition, Disposition::Template);
    }
    for name in ["${FILE}", "envcloak://item/file"] {
        std::fs::write(
            &config,
            format!("{{\"mcpServers\":{{\"s\":{{\"envFile\":\"{name}\"}}}}}}"),
        )
        .unwrap();
        let r =
            scan_config_sources_with_budget(&[source(config.clone())], Budget::default()).unwrap();
        assert!(!r.complete());
        assert!(r.issues.iter().any(|i| i.reason == "unread_env_file"));
    }
}
#[test]
fn findings_obey_shared_candidate_and_occurrence_limits() {
    let d = dir();
    let a = d.path().join("a.json");
    let b = d.path().join("b.json");
    for p in [&a, &b] {
        std::fs::write(
            p,
            br#"{"mcpServers":{"s":{"env":{"A":"one","B":"two"},"envFile":"vars.env"}}}"#,
        )
        .unwrap();
    }
    std::fs::write(d.path().join("vars.env"), b"C=three\nD=four\n").unwrap();
    for limit in [0, 1, 3, 5] {
        for occurrence in [false, true] {
            let budget = if occurrence {
                Budget {
                    occurrences: limit,
                    ..Budget::default()
                }
            } else {
                Budget {
                    candidates: limit,
                    ..Budget::default()
                }
            };
            let r =
                scan_config_sources_with_budget(&[source(a.clone()), source(b.clone())], budget)
                    .unwrap();
            assert!(r.findings.len() <= limit);
            assert!(!r.complete());
            let reason = if occurrence {
                "occurrence_budget"
            } else {
                "candidate_budget"
            };
            assert!(r.issues.iter().any(|i| i.reason == reason));
        }
    }
}

#[test]
fn binding_named_env_file_is_not_an_include_directive() {
    let d = dir();
    for (text, format) in [
        (
            r#"{"servers":{"s":{"env":{"envFile":"fixtureZliteralEnvFile"},"headers":{"envFile":"${NAME}"},"envFile":"actual.env"}}}"#,
            ConfigFormat::Json,
        ),
        (
            "[mcp_servers.s]\nenvFile='actual.env'\n[mcp_servers.s.env]\nenvFile='fixtureZliteralEnvFile'\n[mcp_servers.s.headers]\nenvFile='${NAME}'\n",
            ConfigFormat::Toml,
        ),
    ] {
        let path = d.path().join("config");
        std::fs::write(&path, text).unwrap();
        std::fs::write(d.path().join("actual.env"), b"A=fixtureZincludedValue\n").unwrap();
        let mut descriptor = source(path);
        descriptor.format = format;
        let report = scan_config_sources_with_budget(&[descriptor], Budget::default()).unwrap();
        assert!(report.complete(), "{:?}", report.issues);
        assert_eq!(report.findings.len(), 3);
        assert!(report.findings.iter().any(|f| {
            f.name.ct_eq(b"envFile")
                && f.value
                    .as_ref()
                    .is_some_and(|v| v.ct_eq(b"fixtureZliteralEnvFile"))
        }));
        assert!(report.findings.iter().any(|f| f.name.ct_eq(b"envFile")
            && f.value.is_none()
            && f.disposition == Disposition::Template));
        assert!(report.findings.iter().any(|f| {
            f.name.ct_eq(b"A")
                && f.value
                    .as_ref()
                    .is_some_and(|v| v.ct_eq(b"fixtureZincludedValue"))
        }));
    }
}

#[test]
fn failed_envfile_includes_share_one_attempt_budget() {
    let d = dir();
    let mut servers = serde_json::Map::new();
    for n in 0..70 {
        servers.insert(
            format!("s{n:02}"),
            serde_json::json!({"envFile":format!("missing{n}")}),
        );
    }
    servers.insert("z".into(), serde_json::json!({"envFile":"reached"}));
    std::fs::write(d.path().join("reached"), b"A=fixtureZpastFailedIncludes\n").unwrap();
    let path = d.path().join("mcp.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({"mcpServers":servers})).unwrap(),
    )
    .unwrap();
    let report = scan_config_sources_with_budget(
        &[source(path)],
        Budget {
            files: 64,
            ..Budget::default()
        },
    )
    .unwrap();
    assert!(!report.complete());
    assert!(report.issues.iter().any(|i| i.reason == "file_budget"));
    assert!(report.findings.is_empty());
    assert_eq!(
        report
            .issues
            .iter()
            .filter(|i| i.reason == "not_found")
            .count(),
        63
    );
}

#[test]
fn repeated_envfile_paths_are_read_once() {
    let d = dir();
    let path = d.path().join("mcp.json");
    let servers = (0..70)
        .map(|n| (format!("s{n:02}"), serde_json::json!({"envFile":"shared"})))
        .collect::<serde_json::Map<_, _>>();
    std::fs::write(d.path().join("shared"), b"A=fixtureZsharedIncludeValue\n").unwrap();
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({"mcpServers":servers})).unwrap(),
    )
    .unwrap();
    let report = scan_config_sources_with_budget(
        &[source(path)],
        Budget {
            files: 2,
            ..Budget::default()
        },
    )
    .unwrap();
    assert!(report.complete(), "{report:?}");
    assert_eq!(report.files, 2);
    assert_eq!(report.findings.len(), 1);
}
