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

#[test]
fn included_envfile_leftovers_are_reported_even_when_target_is_missing() {
    use envcloak_scan::{agent_config::scan_config_sources_with_budget, candidates::Budget};
    for format in [ConfigFormat::Json, ConfigFormat::Toml] {
        for present in [false, true] {
            let d = tempfile::tempdir_in("/tmp").unwrap();
            let values = d.path().join("nested");
            std::fs::create_dir(&values).unwrap();
            if present {
                std::fs::write(values.join("values.env"), b"A=fixtureZincludedOriginal\n").unwrap();
            }
            let config = if format == ConfigFormat::Json {
                br#"{"mcpServers":{"s":{"envFile":"nested/values.env"}}}"#.as_slice()
            } else {
                b"[mcp_servers.s]\nenvFile = 'nested/values.env'\n"
            };
            std::fs::write(d.path().join("config"), config).unwrap();
            let mut descriptor = source(d.path(), "config");
            descriptor.format = format;
            for kind in ["new", "swap"] {
                let name = format!(".values.env.envcloak-{kind}-ab.tmp");
                std::fs::write(values.join(name), b"fixtureZretainedIncludeContents").unwrap();
            }
            // Only the approved target's siblings count, not unrelated names.
            std::fs::write(values.join(".other.envcloak-new-ab.tmp"), b"unrelated").unwrap();
            let report = scan_config_sources(&[descriptor.clone()]).unwrap();
            assert_eq!(
                report.leftovers.len(),
                2,
                "included-file leftovers were omitted"
            );
            assert!(!report.complete());
            assert!(
                report
                    .leftovers
                    .iter()
                    .all(|l| l.inspection == "possible_leftover")
            );
            assert!(report.findings.iter().all(|f| {
                f.value
                    .as_ref()
                    .is_none_or(|v| !v.ct_eq(b"fixtureZretainedIncludeContents"))
            }));
            assert!(!format!("{report:?}").contains("fixtureZretainedIncludeContents"));
            for leftover in report.leftovers {
                assert_eq!(
                    std::fs::read(leftover.source.path).unwrap(),
                    b"fixtureZretainedIncludeContents"
                );
            }
            let limited = scan_config_sources_with_budget(
                &[descriptor],
                Budget {
                    files: 3,
                    ..Budget::default()
                },
            )
            .unwrap();
            assert!(!limited.complete());
            assert!(limited.issues.iter().any(|i| i.reason == "file_budget"));
            assert_eq!(
                limited.leftovers.len(),
                1,
                "include sibling discovery escaped the shared budget"
            );
        }
    }
}

#[test]
fn explicit_leftover_sources_and_includes_remain_metadata_only() {
    for include in [false, true] {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let name = ".values.env.envcloak-swap-ab.tmp";
        let bytes = if include {
            b"A=fixtureZdirectLeftoverRead\n".as_slice()
        } else {
            br#"{"env":{"A":"fixtureZdirectLeftoverRead"}}"#
        };
        std::fs::write(d.path().join(name), bytes).unwrap();
        let descriptor = if include {
            let config = serde_json::json!({"mcpServers":{"s":{"envFile":name}}});
            std::fs::write(
                d.path().join("config.json"),
                serde_json::to_vec(&config).unwrap(),
            )
            .unwrap();
            source(d.path(), "config.json")
        } else {
            source(d.path(), name)
        };
        let report = scan_config_sources(&[descriptor]).unwrap();
        assert_eq!(
            report.leftovers.len(),
            1,
            "direct leftover target was read as ordinary content"
        );
        assert!(report.findings.is_empty());
        assert!(!report.complete());
        assert_eq!(std::fs::read(d.path().join(name)).unwrap(), bytes);
    }
}

#[test]
fn included_leftover_symlinks_are_reported_without_following() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::write(
        d.path().join("config.json"),
        br#"{"mcpServers":{"s":{"envFile":"missing.env"}}}"#,
    )
    .unwrap();
    let target = d.path().join("target");
    std::fs::write(&target, b"fixtureZoutsideLeftoverValue").unwrap();
    let name = d.path().join(".missing.env.envcloak-new-ab.tmp");
    std::os::unix::fs::symlink(&target, &name).unwrap();
    let report = scan_config_sources(&[source(d.path(), "config.json")]).unwrap();
    assert_eq!(report.leftovers.len(), 1);
    assert_eq!(report.leftovers[0].inspection, "symlink");
    assert!(report.findings.is_empty());
    assert!(!report.complete());
    assert!(name.is_symlink());
}

#[test]
fn include_leftover_discovery_reuses_reported_metadata() {
    use envcloak_scan::{agent_config::scan_config_sources_with_budget, candidates::Budget};
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let retained = ".values.env.envcloak-new-ab.tmp";
    std::fs::write(d.path().join(retained), b"retained").unwrap();
    std::fs::write(
        d.path().join("values.env"),
        b"A=fixtureZdeduplicatedMetadata\n",
    )
    .unwrap();
    std::fs::write(
        d.path().join("config.json"),
        br#"{"mcpServers":{"s":{"envFile":"values.env"}}}"#,
    )
    .unwrap();
    let report = scan_config_sources_with_budget(
        &[source(d.path(), retained), source(d.path(), "config.json")],
        Budget {
            files: 3,
            ..Budget::default()
        },
    )
    .unwrap();
    assert_eq!(report.leftovers.len(), 1);
    assert_eq!(report.findings.len(), 1);
    assert!(!report.complete());
    assert!(
        !report.issues.iter().any(|i| i.reason == "file_budget"),
        "same leftover was charged twice"
    );
}
