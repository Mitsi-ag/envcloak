//! M2-12 profile decoding, removal eligibility and traversal gates.
#![allow(clippy::unwrap_used)]
use envcloak_core::SecretBytes;
use envcloak_scan::{
    candidates::Disposition,
    open_root,
    profile::{Shell, parse_profile, scan_profiles},
};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::path::Path;

fn fixture() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ec-p")
        .tempdir_in(std::fs::canonicalize(std::env::temp_dir()).expect("temporary root"))
        .unwrap()
}

#[test]
fn profiles_match_independent_bash_oracle_and_keep_removal_separate() {
    let dir = fixture();
    let oracle = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracles/profile.py");
    let output = std::process::Command::new("/usr/bin/python3")
        .arg("-I")
        .arg(oracle)
        .arg(dir.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "oracle failed");
    assert!(output.stderr.is_empty());
    let cases: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for case in cases.as_array().unwrap() {
        let bytes = SecretBytes::from_vec(
            std::fs::read(dir.path().join(case["source_file"].as_str().unwrap())).unwrap(),
        );
        let result = parse_profile(&bytes, Shell::Posix);
        let a = result
            .findings
            .iter()
            .find(|f| f.name.ct_eq(b"EC_ORACLE_A"));
        let template = case["proposed_policy"] == "template_name_only";
        if template {
            assert!(
                a.is_some_and(|f| f.disposition == Disposition::Template && f.value.is_none()),
                "template {}",
                case["name"]
            );
        } else if case["proposed_policy"]
            .as_str()
            .unwrap()
            .starts_with("manual_")
        {
            assert!(!result.complete(), "manual {}", case["name"]);
            assert!(a.is_some_and(|f| f.disposition == Disposition::Manual
                && f.value.is_none()
                && !f.single_complete_line));
        } else {
            let f = a.expect("supported assignment must be found");
            assert_eq!(f.disposition, Disposition::Literal, "{}", case["name"]);
            let v = f.value.as_ref().unwrap();
            #[allow(clippy::disallowed_methods)]
            let digest = Sha256::digest(v.expose_secret())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert!(
                digest == case["expected_a"]["sha256"].as_str().unwrap(),
                "decoded {}",
                case["name"]
            );
            assert_eq!(
                v.len(),
                case["expected_a"]["bytes"].as_u64().unwrap() as usize
            );
            assert_eq!(
                f.single_complete_line,
                case["proposed_whole_line_delete_eligible"]
                    .as_bool()
                    .unwrap(),
                "removal {}",
                case["name"]
            );
        }
    }
}

#[test]
fn profile_roots_refuse_links_fifo_and_report_unreadable() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = fixture();
    std::fs::write(dir.path().join("outside"), b"A=fixture\n").unwrap();
    symlink("outside", dir.path().join(".profile")).unwrap();
    std::fs::write(dir.path().join(".bashrc"), b"A=fixture\n").unwrap();
    std::fs::set_permissions(
        dir.path().join(".bashrc"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    std::fs::write(dir.path().join(".zshrc"), b"B=control\n").unwrap();
    let report = scan_profiles(&open_root(dir.path()).unwrap()).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert!(report.issues.iter().any(|i| i.reason == "symlink"));
    assert!(report.issues.iter().any(|i| i.reason == "unreadable"));
    assert!(!report.complete());
}

#[test]
fn source_expansion_depth_and_count_are_bounded_without_execution() {
    let dir = fixture();
    std::fs::write(
        dir.path().join(".profile"),
        b"source '$HOME/ignored'\n. \"$HOME/one\"\nsource $(false)\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("one"), b"A=one\nsource ~/two\n").unwrap();
    std::fs::write(dir.path().join("two"), b"B=two\n. three\n").unwrap();
    std::fs::write(dir.path().join("three"), b"C=three\n. four\n").unwrap();
    std::fs::write(dir.path().join("four"), b"D=four\n. five\n").unwrap();
    std::fs::write(dir.path().join("five"), b"E=five\n").unwrap();
    let report = scan_profiles(&open_root(dir.path()).unwrap()).unwrap();
    assert_eq!(report.findings.len(), 4);
    assert!(report.issues.iter().any(|i| i.reason == "too_deep"));
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.reason == "source_not_literal")
    );
}

#[test]
fn profile_count_fish_literals_and_ambiguous_context_are_conservative() {
    let d = fixture();
    let mut body = String::new();
    for i in 0..65 {
        body.push_str(&format!(". file{i}\n"));
        std::fs::write(d.path().join(format!("file{i}")), format!("A=value{i}\n")).unwrap();
    }
    std::fs::write(d.path().join(".profile"), body).unwrap();
    let report = scan_profiles(&open_root(d.path()).unwrap()).unwrap();
    assert_eq!(report.files, 64);
    assert!(report.issues.iter().any(|i| i.reason == "too_many_files"));
    let parsed = parse_profile(
        &SecretBytes::copy_from(b"set -x A 'literal value'\nset -x B $OTHER\nset -x C one two\n"),
        Shell::Fish,
    );
    assert!(
        parsed.findings[0]
            .value
            .as_ref()
            .unwrap()
            .ct_eq(b"literal value")
    );
    assert!(parsed.findings[1].value.is_none());
    assert!(parsed.findings[2].value.is_none());
    assert!(!parsed.complete());
    let parsed = parse_profile(
        &SecretBytes::copy_from(b"cat <<'END'\nA=contents\nEND\n"),
        Shell::Posix,
    );
    assert!(!parsed.complete());
    assert!(parsed.findings.iter().all(|f| !f.single_complete_line));
}

#[test]
fn fish_export_scopes_and_comments_preserve_literals() {
    for flag in ["-x", "-gx", "-Ux", "-xg", "-xU"] {
        let r = parse_profile(
            &SecretBytes::from_vec(
                format!("set {flag} NAME 'fixture value' # $OTHER `ignored`\n").into_bytes(),
            ),
            Shell::Fish,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert_eq!(f.disposition, Disposition::Literal);
        assert!(f.value.as_ref().unwrap().ct_eq(b"fixture value"));
        assert!(f.single_complete_line);
    }
}
