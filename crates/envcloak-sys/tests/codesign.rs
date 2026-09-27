//! macOS: `Hardening::hardened_runtime` reads the kernel's code-signing
//! flags. A copy of this test binary signed ad hoc with the hardened runtime
//! must report true; the linker's plain ad hoc signature must report false.
#![allow(clippy::unwrap_used)]

const CHILD_ENV: &str = "ENVCLOAK_SYS_CODESIGN_CHILD";

/// Runs only as the child started by the test below.
#[test]
fn report_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    println!(
        "hardened_runtime={:?}",
        envcloak_sys::hardening_status().hardened_runtime
    );
}

#[cfg(target_os = "macos")]
fn run_child(exe: &std::path::Path) -> String {
    let out = std::process::Command::new(exe)
        .args(["--exact", "report_child", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "child failed: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[cfg(target_os = "macos")]
#[test]
fn hardened_runtime_flag_follows_the_signature() {
    use std::process::Command;

    let exe = std::env::current_exe().unwrap();
    assert!(
        run_child(&exe).contains("hardened_runtime=Some(false)"),
        "a linker-signed test binary has no hardened runtime"
    );

    let dir = tempfile::Builder::new()
        .prefix("ecsig")
        .tempdir_in("/tmp")
        .unwrap();
    let copy = dir.path().join("signed-copy");
    std::fs::copy(&exe, &copy).unwrap();
    let status = Command::new("codesign")
        .args(["--force", "--sign", "-", "--options", "runtime"])
        .arg(&copy)
        .status()
        .unwrap();
    assert!(status.success(), "codesign failed");
    let out = run_child(&copy);
    assert!(out.contains("hardened_runtime=Some(true)"), "{out}");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn hardened_runtime_is_not_applicable() {
    assert_eq!(envcloak_sys::hardening_status().hardened_runtime, None);
}
