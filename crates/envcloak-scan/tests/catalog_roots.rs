//! Catalog system aliases remain distinct from user-controlled symlinks.
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used)]
use envcloak_scan::{
    candidates::Budget,
    source::{ConfigFormat, ConfigSource, SourceKind},
    transcript::scan_transcript_sources,
};
use std::os::unix::fs::symlink;
fn source(path: std::path::PathBuf) -> ConfigSource {
    ConfigSource {
        path,
        format: ConfigFormat::Raw,
        source_kind: SourceKind::Transcript,
        label: "fixture".into(),
        names: None,
    }
}
#[cfg(target_os = "macos")]
#[test]
fn catalog_roots_accept_the_system_var_alias_but_refuse_user_links() {
    let base = std::process::Command::new("/usr/bin/getconf")
        .arg("DARWIN_USER_TEMP_DIR")
        .env_clear()
        .output()
        .unwrap();
    assert!(base.status.success());
    let base = std::path::PathBuf::from(String::from_utf8(base.stdout).unwrap().trim());
    let physical = std::fs::canonicalize(&base).unwrap();
    assert!(physical.starts_with("/private/var/folders"));
    let d = tempfile::tempdir_in(physical).unwrap();
    let alias = std::path::Path::new("/var").join(d.path().strip_prefix("/private/var").unwrap());
    std::fs::write(d.path().join("store"), b"fixtureZsystemAliasValue").unwrap();
    let mut found = false;
    let report = scan_transcript_sources(
        &[source(alias.join("store"))],
        Budget::default(),
        &mut |c| {
            found |= c.value.ct_eq(b"fixtureZsystemAliasValue");
            true
        },
    )
    .unwrap();
    assert!(report.complete(), "{report:?}");
    assert!(found);
    symlink(d.path(), d.path().join("user-link")).unwrap();
    let report = scan_transcript_sources(
        &[source(alias.join("user-link/store"))],
        Budget::default(),
        &mut |_| panic!("followed a user link"),
    )
    .unwrap();
    assert!(!report.complete());
    assert!(report.issues.iter().any(|i| i.reason == "symlink"));
}
