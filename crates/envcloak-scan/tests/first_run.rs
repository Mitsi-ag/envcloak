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
        b"[default]\naws_secret_access_key = first\naws_secret_access_key = second\n".to_vec(),
        b"[broken\naws_secret_access_key = first\n".to_vec(),
    ] {
        let r = parse_aws(&SecretBytes::from_vec(bytes));
        assert!(!r.complete());
        assert!(r.findings.iter().all(|f| !f.single_complete_line));
        assert!(!format!("{r:?}").contains("first"));
    }
    assert!(parse_aws(&SecretBytes::copy_from(b"")).complete());
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
        std::fs::Permissions::from_mode(0),
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
