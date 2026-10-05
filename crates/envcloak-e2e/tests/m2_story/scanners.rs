//! M2-12: the pinned hosts author config and transcript bytes, then the actual
//! scanners read only those isolated homes. Counts, never values, are reported.
use envcloak_agents::locations::Locations;
use envcloak_scan::candidates::{Budget, Candidates};
use envcloak_scan::source::{ConfigFormat, ConfigSource, SourceKind};
use envcloak_testkit::agents::{AgentHome, Host, HostFlags, Installed, require};
use envcloak_testkit::fresh_seed;
use serde_json::json;
use std::ffi::OsString;
use std::path::Path;

fn scanner_story(host: Host) {
    let versions = Path::new(env!("CARGO_MANIFEST_DIR")).join("agents/versions.toml");
    let Some(installed) = require(
        Installed::find(&versions, host.id(), "native"),
        "M2-12 scanner story",
    ) else {
        return;
    };
    let agent = AgentHome::start(host, installed);
    let literal = format!("ecscanZ{:016x}{:016x}", fresh_seed(), fresh_seed());
    let added = match host {
        Host::ClaudeCode => agent.host_cli(&[
            "mcp",
            "add-json",
            "--scope",
            "user",
            "fixture",
            &json!({"command":"/usr/bin/true","env":{"TOKEN":literal}}).to_string(),
        ]),
        Host::Codex => agent.host_cli(&[
            "mcp",
            "add",
            "fixture",
            "--env",
            &format!("TOKEN={literal}"),
            "--",
            "/usr/bin/true",
        ]),
    };
    assert!(added.status.success(), "host config command failed");
    let home = agent.home_dir();
    let codex = agent.codex_home();
    let tmp = agent.claude_tmp();
    let catalog = Locations::new(&|key| match key {
        "HOME" => Some(OsString::from(&home)),
        "CODEX_HOME" => Some(OsString::from(&codex)),
        "CLAUDE_CODE_TMPDIR" => Some(OsString::from(&tmp)),
        _ => None,
    })
    .unwrap();
    let report = envcloak_scan::scan_config_sources(&catalog.config_sources()).unwrap();
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f
                .value
                .as_ref()
                .is_some_and(|v| v.ct_eq(literal.as_bytes())))
            .count(),
        1,
        "host-authored binding missing"
    );
    let flags = match host {
        Host::ClaudeCode => HostFlags::claude("default", &[]),
        Host::Codex => HostFlags::codex("read-only", "never"),
    };
    let run = agent.run(
        &json!({"steps":[{"say":literal}]}),
        "Reply with the fixture text.",
        &flags,
        &home,
    );
    assert!(run.output.status.success(), "scripted host failed");
    assert!(run.model.clean());
    // Scan the host's real transcript root, not a hand-shaped event fixture.
    let (path, format) = match host {
        Host::ClaudeCode => (home.join(".claude/projects"), ConfigFormat::Mixed),
        Host::Codex => (codex.join("sessions"), ConfigFormat::Jsonl),
    };
    let source = ConfigSource {
        path,
        format,
        source_kind: SourceKind::Transcript,
        label: "host oracle".into(),
        names: None,
    };
    let mut candidates = Candidates::new(Budget::default()).unwrap();
    let report = envcloak_scan::transcript::scan_transcript_sources(
        &[source],
        Budget::default(),
        &mut |c| candidates.insert(c),
    )
    .unwrap();
    assert!(report.complete(), "{:?}", report.issues);
    let matches: Vec<_> = candidates
        .entries()
        .iter()
        .filter(|c| c.value.ct_eq(literal.as_bytes()))
        .collect();
    assert_eq!(matches.len(), 1, "real transcript fixture missing");
    assert!(!matches[0].occurrences.is_empty());
    assert!(matches[0].occurrences.iter().all(|o| o.stamp.is_some()));
    agent.check_isolated();
}
#[test]
fn claude_config_and_transcript_are_scanned() {
    scanner_story(Host::ClaudeCode);
}
#[test]
fn codex_config_and_transcript_are_scanned() {
    scanner_story(Host::Codex);
}

#[test]
fn gate8_serializer_escapes_retain_the_raw_span() {
    let emitter = envcloak_e2e::target_dir().join("ec-emit-serde");
    envcloak_testkit::assert_fresh(&emitter, "envcloak-e2e");
    let fixture = format!("ecscanZ{:016x}\\{:016x}", fresh_seed(), fresh_seed());
    let output = std::process::Command::new(emitter)
        .arg("FIXTURE")
        .env_clear()
        .env("FIXTURE", &fixture)
        .output()
        .unwrap();
    assert!(output.status.success());
    let end = output.stdout.iter().position(|b| *b == 0).unwrap();
    let encoded = &output.stdout[..end];
    let mut matched = false;
    let report = envcloak_scan::transcript::scan_reader(
        &mut std::io::Cursor::new(encoded),
        ConfigFormat::Jsonl,
        Default::default(),
        Budget::default(),
        &mut |candidate| {
            if candidate.value.ct_eq(fixture.as_bytes()) {
                matched = true;
                assert_eq!(candidate.occurrence.range, 1..encoded.len() as u64 - 1);
            }
            true
        },
    )
    .unwrap();
    assert!(report.complete());
    assert!(matched, "gate-8 serializer reading missing");
}
