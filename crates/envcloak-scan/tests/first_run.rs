//! M2-16: independently authored files, conservative cleanup and gate 15.
#![allow(clippy::unwrap_used)]
use envcloak_core::SecretBytes;
use envcloak_scan::aws::{parse_aws, scan_aws};
use envcloak_scan::first_run::comment_assignments;
use envcloak_scan::profile::{Shell, parse_profile};
use envcloak_scan::{MAX_DOTENV, open_root};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::Command;

#[test]
fn aws_cli_is_the_file_oracle() {
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let value = "fixture".repeat(4);
    for (name, content) in [
        ("aws_access_key_id", value.as_str()),
        ("aws_secret_access_key", value.as_str()),
        ("aws_session_token", value.as_str()),
        ("region", "ap-southeast-2"),
        ("output", "json"),
    ] {
        let out = Command::new("aws")
            .env_clear()
            .env("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")
            .env("HOME", home.path())
            .env("AWS_CONFIG_FILE", home.path().join(".aws/config"))
            .env(
                "AWS_SHARED_CREDENTIALS_FILE",
                home.path().join(".aws/credentials"),
            )
            .args(["configure", "set", name, content, "--profile", "fixture"])
            .output()
            .expect("the real AWS CLI is required for the file oracle");
        assert!(out.status.success(), "AWS fixture writer failed");
    }
    let report = scan_aws(&open_root(home.path()).unwrap());
    assert!(report.complete(), "AWS CLI output must parse");
    assert_eq!(
        report.findings.len(),
        3,
        "keys only, never region or output"
    );
    for f in &report.findings {
        assert!(f.value.as_ref().unwrap().ct_eq(value.as_bytes()));
        assert!(f.single_complete_line);
    }
}

#[test]
fn aws_hostile_grammar_is_explicit_and_value_free() {
    for bytes in [
        vec![255],
        vec![0],
        vec![b'a'; MAX_DOTENV + 1],
        b"[default]\naws_secret_access_key = first\n continuation\n".to_vec(),
        b"[default]\naws_secret_access_key = first\n  part=two\n".to_vec(),
        "[default]\naws_secret_access_key = first\n\u{a0}part=two\n"
            .as_bytes()
            .to_vec(),
        b"[default]\nAWS_SECRET_ACCESS_KEY = first\naws_secret_access_key = second\n".to_vec(),
        b"[default]\naws_secret_access_key = first\naws_secret_access_key = second\n".to_vec(),
        b"[default]\naws_access_key_id = first\n[default]\naws_secret_access_key = second\n"
            .to_vec(),
        b"[broken\naws_secret_access_key = first\n".to_vec(),
        b"[default]\naws_session_token: first==\n  part=two\n".to_vec(),
        b"[default]\naws_secret_access_key: first=part\nAWS_SECRET_ACCESS_KEY = second\n".to_vec(),
    ] {
        let r = parse_aws(&SecretBytes::from_vec(bytes));
        assert!(!r.complete());
        assert!(r.findings.iter().all(|f| !f.single_complete_line));
        assert!(r.findings.iter().all(|f| f.value.is_none()));
        assert!(!format!("{r:?}").contains("first"));
    }
    assert!(parse_aws(&SecretBytes::copy_from(b"")).complete());
}

#[test]
fn aws_option_casing_matches_python_ini_oracle() {
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let path = home.path().join("fixture.ini");
    let bytes = b"[default]\nAWS_ACCESS_KEY_ID = first fixture\nAws_Secret_Access_Key = second fixture\nAWS_SESSION_TOKEN = third fixture\nregion = fixture-region\n[other]\naws_secret_access_key = fourth fixture\n";
    std::fs::write(&path, bytes).unwrap();
    let out = Command::new("/usr/bin/python3")
        .env_clear()
        .env("HOME", home.path())
        .args(["-I", "-c", "import configparser,json,sys; p=configparser.RawConfigParser(); p.read(sys.argv[1]); print(json.dumps([(k.upper(),v) for s in p.sections() for k,v in p.items(s) if k.startswith('aws_')]))"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let expected: Vec<(String, String)> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(expected.len(), 4);
    let report = parse_aws(&SecretBytes::copy_from(bytes));
    assert!(report.complete());
    assert_eq!(report.findings.len(), expected.len());
    for (finding, (name, value)) in report.findings.iter().zip(expected) {
        assert!(finding.name.ct_eq(name.as_bytes()));
        assert!(finding.value.as_ref().unwrap().ct_eq(value.as_bytes()));
    }
}

#[test]
fn aws_delimiters_match_python_ini_oracle() {
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let path = home.path().join("fixture.ini");
    // Hand-written reader syntax: aws configure set only writes equals.
    let bytes = b"[default]\naws_access_key_id: first fixture\nAws_Secret_Access_Key: second fixture=embedded\naws_session_token: third fixture==\n[other]\naws_secret_access_key = fourth fixture:retained=tail\n";
    std::fs::write(&path, bytes).unwrap();
    let out = Command::new("/usr/bin/python3")
        .env_clear()
        .env("HOME", home.path())
        .args(["-I", "-c", "import configparser,json,sys; p=configparser.RawConfigParser(); p.read(sys.argv[1]); print(json.dumps([(k.upper(),v) for s in p.sections() for k,v in p.items(s)]))"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let expected: Vec<(String, String)> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(expected.len(), 4);
    let input = SecretBytes::copy_from(bytes);
    let report = parse_aws(&input);
    assert!(report.complete());
    assert_eq!(report.findings.len(), expected.len());
    for (finding, (name, value)) in report.findings.iter().zip(expected) {
        assert!(finding.name.ct_eq(name.as_bytes()));
        assert!(finding.value.as_ref().unwrap().ct_eq(value.as_bytes()));
        assert!(finding.single_complete_line);
    }
    let edited = comment_assignments(&input, &report.findings, &[(1, "fixture/second")]).unwrap();
    assert!(edited.ct_eq(b"[default]\naws_access_key_id: first fixture\n# envcloak: fixture/second; use envcloak run\naws_session_token: third fixture==\n[other]\naws_secret_access_key = fourth fixture:retained=tail\n"));
}

#[test]
fn aws_continuation_context_matches_python_ini_oracle() {
    for (bytes, credential) in [
        (
            "[default]\nregion = first\n  aws_secret_access_key = second\n",
            None,
        ),
        (
            "[default]\naws_secret_access_key = first\n  [other]\n",
            Some("first\n[other]"),
        ),
    ] {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let path = home.path().join("fixture.ini");
        std::fs::write(&path, bytes).unwrap();
        let out = Command::new("/usr/bin/python3")
            .env_clear()
            .env("HOME", home.path())
            .args(["-I", "-c", "import configparser,json,sys; p=configparser.RawConfigParser(); p.read(sys.argv[1]); print(json.dumps([p.sections(), p.get('default','aws_secret_access_key',fallback=None)]))"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success());
        let expected: (Vec<String>, Option<String>) = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(expected.0, ["default"]);
        assert_eq!(expected.1.as_deref(), credential);
        let report = parse_aws(&SecretBytes::copy_from(bytes.as_bytes()));
        assert!(!report.complete());
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.value.is_none() && !f.single_complete_line)
        );
    }
}

#[test]
fn gate15_machine_hard_links_remove_line_eligibility() {
    for name in [
        ".zshrc",
        "included/profile",
        ".aws/credentials",
        ".aws/config",
    ] {
        for linked in [false, true] {
            let home = tempfile::tempdir_in("/tmp").unwrap();
            let path = home.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            if name == "included/profile" {
                std::fs::write(home.path().join(".zshrc"), b"source included/profile\n").unwrap();
            }
            let aws = name.starts_with(".aws/");
            let bytes: &[u8] = if aws {
                b"[default]\naws_secret_access_key = fixture value\n"
            } else {
                b"export SECRET_TOKEN='fixture value'\n"
            };
            std::fs::write(&path, bytes).unwrap();
            if linked {
                std::fs::hard_link(&path, home.path().join("alias")).unwrap();
            }
            let root = open_root(home.path()).unwrap();
            let report = if aws {
                scan_aws(&root)
            } else {
                envcloak_scan::profile::scan_profiles(&root).unwrap()
            };
            assert_eq!(report.findings.len(), 1);
            assert!(report.findings[0].value.is_some());
            assert_eq!(report.findings[0].single_complete_line, !linked, "{name}");
            assert_eq!(
                report.issues.iter().any(|i| i.reason == "hard_link"),
                linked,
                "{name}"
            );
        }
    }
}

#[test]
fn zsh_equals_expansion_matches_the_shell_oracle() {
    use envcloak_scan::candidates::Disposition;
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let command = "fixture_command";
    let executable = home.path().join(command);
    std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (rhs, literal) in [
        ("=fixture_command", false),
        ("prefix:=fixture_command", false),
        ("''=fixture_command", false),
        ("\"\"=fixture_command", false),
        ("'prefix:'=fixture_command", false),
        ("\"prefix:\"=fixture_command", false),
        ("prefix:''=fixture_command", false),
        ("prefix\\:=fixture_command", false),
        ("\\\n=fixture_command", false),
        ("'=fixture_command'", true),
        ("'='fixture_command", true),
        ("\"=\"fixture_command", true),
        ("\"=fixture_command\"", true),
        ("\\=fixture_command", true),
        ("prefix=fixture_command", true),
        ("'prefix'=fixture_command", true),
        ("'prefix:'\\=fixture_command", true),
    ] {
        for exported in [false, true] {
            let source = format!(
                "{}SECRET_TOKEN={rhs}\n",
                if exported { "export " } else { "" }
            );
            let script = format!("{source}printf '%s' \"$SECRET_TOKEN\"");
            let out = Command::new("/bin/zsh")
                .env_clear()
                .env("HOME", home.path())
                .env("PATH", home.path())
                .args(["-f", "-c", &script])
                .output()
                .expect("zsh is required for the profile grammar oracle");
            assert!(out.status.success());
            assert!(out.stderr.is_empty());
            if !literal {
                assert!(
                    out.stdout
                        .ends_with(executable.as_os_str().as_encoded_bytes())
                );
            }
            let input = SecretBytes::copy_from(source.as_bytes());
            let report = parse_profile(&input, Shell::Posix);
            assert_eq!(report.findings.len(), 1);
            let found = &report.findings[0];
            if literal {
                assert!(report.complete());
                assert!(found.value.as_ref().unwrap().ct_eq(&out.stdout));
                assert!(found.single_complete_line);
                assert!(
                    comment_assignments(&input, &report.findings, &[(0, "fixture/key")]).is_ok()
                );
            } else {
                assert!(!report.complete());
                assert_eq!(found.disposition, Disposition::Manual);
                assert!(found.value.is_none());
                assert!(!found.single_complete_line);
                assert!(
                    comment_assignments(&input, &report.findings, &[(0, "fixture/key")]).is_err()
                );
            }
        }
    }
    // Source paths share the word decoder. An expansion must never cause
    // the scanner to read a literal lookalike file instead of the shell target.
    std::fs::write(
        home.path().join("=fixture_command"),
        b"SECRET_TOKEN=fixtureValueForLookalike\n",
    )
    .unwrap();
    for spelling in [
        "=fixture_command",
        "''=fixture_command",
        "\"\"=fixture_command",
    ] {
        std::fs::write(home.path().join(".zshrc"), format!("source {spelling}\n")).unwrap();
        let report =
            envcloak_scan::profile::scan_profiles(&open_root(home.path()).unwrap()).unwrap();
        assert!(!report.complete());
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.reason == "source_not_literal")
        );
        assert!(report.findings.is_empty());
        assert_eq!(report.files, 1);
    }
    std::fs::write(home.path().join(".zshrc"), b"source '=fixture_command'\n").unwrap();
    let report = envcloak_scan::profile::scan_profiles(&open_root(home.path()).unwrap()).unwrap();
    assert!(report.complete());
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.files, 2);
}

#[test]
fn review_profile_include_and_aws_leftovers_survive_missing_originals() {
    for name in [
        ".zshrc",
        "included/profile",
        ".aws/credentials",
        ".aws/config",
    ] {
        for present in [false, true] {
            for operation in ["new", "swap", "del"] {
                let home = tempfile::tempdir_in("/tmp").unwrap();
                let path = home.path().join(name);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                if name == "included/profile" {
                    std::fs::write(home.path().join(".zshrc"), b"source included/profile\n")
                        .unwrap();
                }
                if present {
                    std::fs::write(&path, b"# retained\n").unwrap();
                }
                let sibling = path.with_file_name(format!(
                    ".{}.envcloak-{operation}-{}.tmp",
                    path.file_name().unwrap().to_str().unwrap(),
                    "a".repeat(16)
                ));
                std::fs::write(&sibling, b"fixture plaintext").unwrap();
                let root = open_root(home.path()).unwrap();
                let report = if name.starts_with(".aws/") {
                    scan_aws(&root)
                } else {
                    envcloak_scan::profile::scan_profiles(&root).unwrap()
                };
                assert!(!report.complete(), "{name}: {operation}, present={present}");
                assert_eq!(
                    report.leftovers.len(),
                    1,
                    "{name}: {operation}, present={present}"
                );
                assert_eq!(
                    report.leftovers[0].source.path,
                    std::fs::canonicalize(&sibling).unwrap()
                );
                assert_eq!(std::fs::read(&sibling).unwrap(), b"fixture plaintext");
            }
        }
    }
}

#[test]
fn review_config_selection_covers_json_toml_and_each_include() {
    use envcloak_scan::source::{ConfigFormat, ConfigSource, SourceKind};
    for (format, config) in [
        (
            ConfigFormat::Json,
            "{\"mcpServers\":{\"fixture\":{\"command\":\"fixture\",\"envFile\":\"Dropbox/fixture.env\"}}}",
        ),
        (
            ConfigFormat::Toml,
            "[mcp_servers.fixture]\ncommand = 'fixture'\nenvFile = 'Dropbox/fixture.env'\n",
        ),
    ] {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let root = open_root(home.path()).unwrap();
        let path = root.path().join("config");
        std::fs::write(&path, config).unwrap();
        std::fs::create_dir(root.path().join("Dropbox")).unwrap();
        let value = "fixture".repeat(4);
        std::fs::write(
            root.path().join("Dropbox/fixture.env"),
            format!("TOKEN={value}\n"),
        )
        .unwrap();
        let sources = [ConfigSource {
            path,
            format,
            source_kind: SourceKind::McpConfig,
            label: "fixture".into(),
            names: None,
        }];
        let scan = |allow: &dyn Fn(&std::path::Path) -> bool| {
            envcloak_scan::agent_config::scan_config_sources_selected(
                &sources,
                Default::default(),
                allow,
            )
            .unwrap()
        };
        let denied = scan(&|p| !p.components().any(|c| c.as_os_str() == "Dropbox"));
        assert!(denied.findings.iter().all(|f| f.value.is_none()));
        assert!(denied.issues.iter().any(|i| i.reason == "volume_opt_in"));
        let allowed = scan(&|_| true);
        assert!(allowed.complete());
        assert!(
            allowed
                .findings
                .iter()
                .any(|f| f.value.as_ref().is_some_and(|v| v.ct_eq(value.as_bytes())))
        );
        let denied_root = scan(&|_| false);
        assert!(denied_root.findings.is_empty());
        assert!(!denied_root.complete());
        assert_eq!(denied_root.files, 0);
        assert_eq!(denied_root.bytes, 0);
        assert_eq!(denied_root.issues[0].source.path, sources[0].path);
    }
}

#[test]
fn review_project_directory_discovery_has_an_explicit_limit() {
    let home = tempfile::tempdir_in("/tmp").unwrap();
    for name in ["a", "b"] {
        std::fs::create_dir(home.path().join(name)).unwrap();
    }
    let root = open_root(home.path()).unwrap();
    let options = envcloak_scan::WalkOptions {
        recursive: true,
        max_dirs: 2,
        ..Default::default()
    };
    let mut walk = envcloak_scan::walk_dotenv(&root, &options);
    assert!(
        walk.by_ref()
            .any(|f| f.is_err_and(|e| e.kind.token() == "limited"))
    );
    assert_eq!(walk.directories().len(), 2);
}

#[test]
fn review_walk_reports_file_limits_in_one_directory_and_across_directories() {
    for nested in [false, true] {
        for count in [2, 3] {
            let home = tempfile::tempdir_in("/tmp").unwrap();
            for n in 0..count {
                let parent = if nested {
                    home.path().join(format!("p{n}"))
                } else {
                    home.path().to_path_buf()
                };
                std::fs::create_dir_all(&parent).unwrap();
                std::fs::write(parent.join(format!(".env.p{n}")), b"").unwrap();
            }
            let root = open_root(home.path()).unwrap();
            let options = envcloak_scan::WalkOptions {
                recursive: true,
                max_files: 2,
                ..Default::default()
            };
            let found = envcloak_scan::walk_dotenv(&root, &options).collect::<Vec<_>>();
            assert_eq!(found.iter().filter(|f| f.is_ok()).count(), 2);
            assert_eq!(
                found
                    .iter()
                    .any(|f| f.as_ref().is_err_and(|e| e.kind.token() == "limited")),
                count == 3
            );
        }
    }
}

#[test]
fn gate15_aws_and_profiles_never_follow_special_files() {
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let outside = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::create_dir(home.path().join(".aws")).unwrap();
    std::fs::write(outside.path().join("fixture"), b"[default]\n").unwrap();
    symlink(
        outside.path().join("fixture"),
        home.path().join(".aws/credentials"),
    )
    .unwrap();
    let root = open_root(home.path()).unwrap();
    let r = scan_aws(&root);
    assert!(!r.complete());
    assert!(r.findings.is_empty());
    std::fs::remove_file(home.path().join(".aws/credentials")).unwrap();
    let out = Command::new("/usr/bin/mkfifo")
        .env_clear()
        .arg(home.path().join(".aws/credentials"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!scan_aws(&root).complete());
    let big = std::fs::File::create(home.path().join(".aws/config")).unwrap();
    big.set_len(2 << 30).unwrap();
    assert!(!scan_aws(&root).complete());
    symlink(outside.path().join("fixture"), home.path().join(".zshrc")).unwrap();
    assert!(
        !envcloak_scan::profile::scan_profiles(&root)
            .unwrap()
            .complete()
    );
    std::fs::remove_file(home.path().join(".aws/config")).unwrap();
    std::fs::write(home.path().join(".aws/config"), b"[default]\n").unwrap();
    std::fs::set_permissions(
        home.path().join(".aws/config"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    assert!(!scan_aws(&root).complete());
}

#[test]
fn gate16_only_complete_single_lines_are_commented() {
    let input =
        SecretBytes::copy_from(b"# keep\nexport TOKEN='literal fixture value'\nPORT=8080\n");
    let parsed = parse_profile(&input, Shell::Posix);
    let edited = comment_assignments(&input, &parsed.findings, &[(0, "token/profile")]).unwrap();
    assert!(edited.ct_eq(b"# keep\n# envcloak: token/profile; use envcloak run\nPORT=8080\n"));
    for source in [
        "export TOKEN='literal\nfixture'\n",
        "export TOKEN=first\\\nsecond\n",
        "export TOKEN=literal; echo keep\n",
        "export TOKEN=$OTHER\n",
    ] {
        let input = SecretBytes::copy_from(source.as_bytes());
        let parsed = parse_profile(&input, Shell::Posix);
        assert!(comment_assignments(&input, &parsed.findings, &[(0, "token/profile")]).is_err());
    }
}

#[test]
#[allow(clippy::disallowed_methods)] // Only generated oracle fixtures are written and sourced.
fn gate16_profile_edits_preserve_bash_oracle_bindings() {
    use secrecy::ExposeSecret;
    let dir = tempfile::Builder::new()
        .prefix("ec-p")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .unwrap();
    let oracle = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracles/profile.py");
    let output = Command::new("/usr/bin/python3")
        .arg("-I")
        .arg(oracle)
        .arg(dir.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success() && output.stderr.is_empty());
    let cases: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut edited = 0;
    for case in cases.as_array().unwrap() {
        if case["proposed_whole_line_delete_eligible"] != true || case["include_file"].is_string() {
            continue;
        }
        let mut bytes =
            std::fs::read(dir.path().join(case["source_file"].as_str().unwrap())).unwrap();
        bytes.extend_from_slice(b"EC_SURVIVE=42\n");
        let input = SecretBytes::from_vec(bytes);
        let parsed = parse_profile(&input, Shell::Posix);
        let index = parsed
            .findings
            .iter()
            .position(|f| f.name.ct_eq(b"EC_ORACLE_A"))
            .unwrap();
        let after =
            comment_assignments(&input, &parsed.findings, &[(index, "fixture/profile")]).unwrap();
        let path = dir.path().join("edited.sh");
        std::fs::write(&path, after.expose_secret()).unwrap();
        let out = Command::new("/bin/bash").args(["--noprofile","--norc","-c",
            "unset EC_ORACLE_A EC_SURVIVE; . \"$1\" >/dev/null 2>/dev/null; test \"${EC_ORACLE_A+x}\" != x && test \"$EC_SURVIVE\" = 42", "oracle"])
            .arg(&path).env_clear().env("HOME",dir.path()).env("PATH","/usr/bin:/bin").output().unwrap();
        assert!(
            out.status.success(),
            "Bash removal or preservation witness failed"
        );
        assert!(out.stdout.is_empty() && out.stderr.is_empty());
        edited += 1;
    }
    assert!(edited >= 60, "independent removal corpus was not exercised");
}
