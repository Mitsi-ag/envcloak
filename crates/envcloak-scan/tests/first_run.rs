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
        b"[default]\nAWS_SECRET_ACCESS_KEY = first\naws_secret_access_key = second\n".to_vec(),
        b"[default]\naws_secret_access_key = first\naws_secret_access_key = second\n".to_vec(),
        b"[broken\naws_secret_access_key = first\n".to_vec(),
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
