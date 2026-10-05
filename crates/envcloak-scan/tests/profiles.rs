//! M2-12 profile decoding, removal eligibility and traversal gates.
#![allow(clippy::unwrap_used)]
use std::path::Path;
use envcloak_core::SecretBytes;
use envcloak_scan::{open_root, profile::{parse_profile, scan_profiles, Shell}, candidates::Disposition};
use sha2::{Digest, Sha256};
use secrecy::ExposeSecret;

fn fixture() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("ec-p").tempdir_in("/tmp/ec-target-E").unwrap()
}

#[test]
fn profiles_match_independent_bash_oracle_and_keep_removal_separate() {
    let dir = fixture();
    let oracle = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracles/profile.py");
    let output = std::process::Command::new("/usr/bin/python3").arg("-I").arg(oracle).arg(dir.path())
        .env_clear().env("PATH", "/usr/bin:/bin").env("HOME",dir.path()).output().unwrap();
    assert!(output.status.success(), "oracle failed");
    assert!(output.stderr.is_empty());
    let cases: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut literals = 0;
    for case in cases.as_array().unwrap() {
        let bytes = SecretBytes::from_vec(std::fs::read(dir.path().join(case["source_file"].as_str().unwrap())).unwrap());
        let result = parse_profile(&bytes, Shell::Posix);
        let a = result.findings.iter().find(|f| f.name.ct_eq(b"EC_ORACLE_A"));
        let template = case["proposed_policy"] == "template_name_only";
        if template {
            assert!(a.is_some_and(|f| f.disposition == Disposition::Template && f.value.is_none()), "template {}",case["name"]);
        } else if let Some(f) = a.filter(|f| f.value.is_some()) {
            let v = f.value.as_ref().unwrap();
            #[allow(clippy::disallowed_methods)]
            let digest = Sha256::digest(v.expose_secret()).iter().map(|b|format!("{b:02x}")).collect::<String>();
            assert!(digest == case["expected_a"]["sha256"].as_str().unwrap(), "decoded {}",case["name"]);
            assert_eq!(v.len(), case["expected_a"]["bytes"].as_u64().unwrap() as usize);
            if f.single_complete_line { assert_eq!(case["proposed_whole_line_delete_eligible"], true,"removal {}",case["name"]); }
            literals += 1;
        } else { assert!(!result.complete(), "silently omitted {}",case["name"]); }
    }
    assert!(literals >= 50, "ordinary literal syntax must work");
}

#[test]
fn profile_roots_refuse_links_fifo_and_report_unreadable() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = fixture();
    std::fs::write(dir.path().join("outside"),b"A=fixture\n").unwrap();
    symlink("outside",dir.path().join(".profile")).unwrap();
    std::fs::write(dir.path().join(".bashrc"),b"A=fixture\n").unwrap();
    std::fs::set_permissions(dir.path().join(".bashrc"),std::fs::Permissions::from_mode(0)).unwrap();
    std::fs::write(dir.path().join(".zshrc"),b"B=control\n").unwrap();
    let report = scan_profiles(&open_root(dir.path()).unwrap()).unwrap();
    assert_eq!(report.findings.len(),1);
    assert!(report.issues.iter().any(|i| i.reason == "symlink"));
    assert!(report.issues.iter().any(|i| i.reason == "unreadable"));
    assert!(!report.complete());
}

#[test]
fn source_expansion_depth_and_count_are_bounded_without_execution() {
    let dir=fixture();
    std::fs::write(dir.path().join(".profile"),b"source '$HOME/ignored'\n. \"$HOME/one\"\nsource $(false)\n").unwrap();
    std::fs::write(dir.path().join("one"),b"A=one\nsource ~/two\n").unwrap();
    std::fs::write(dir.path().join("two"),b"B=two\n. three\n").unwrap();
    std::fs::write(dir.path().join("three"),b"C=three\n. four\n").unwrap();
    std::fs::write(dir.path().join("four"),b"D=four\n. five\n").unwrap();
    std::fs::write(dir.path().join("five"),b"E=five\n").unwrap();
    let report=scan_profiles(&open_root(dir.path()).unwrap()).unwrap();
    assert_eq!(report.findings.len(),4);
    assert!(report.issues.iter().any(|i| i.reason == "too_deep"));
    assert!(report.issues.iter().any(|i| i.reason == "source_not_literal"));
}
