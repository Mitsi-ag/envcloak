//! macOS: `Hardening::hardened_runtime` reads the kernel's code-signing
//! flags. A copy of this test binary signed ad hoc with the hardened runtime
//! must report true; the linker's plain ad hoc signature must report false,
//! and so must a hardened-runtime signature that carries `get-task-allow`,
//! which lets any same-user debugger attach.
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

/// Entitlements that let a debugger attach to the process.
#[cfg(target_os = "macos")]
const GET_TASK_ALLOW: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>\n";

/// A copy of this test binary in `dir`, signed ad hoc with the hardened
/// runtime and, if given, the entitlements in `entitlements`.
#[cfg(target_os = "macos")]
fn runtime_signed_copy(
    dir: &std::path::Path,
    name: &str,
    entitlements: Option<&str>,
) -> std::path::PathBuf {
    let copy = dir.join(name);
    std::fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();
    let mut cmd = std::process::Command::new("codesign");
    cmd.args(["--force", "--sign", "-", "--options", "runtime"]);
    if let Some(plist) = entitlements {
        let path = dir.join(format!("{name}.entitlements"));
        std::fs::write(&path, plist).unwrap();
        cmd.arg("--entitlements").arg(path);
    }
    let status = cmd.arg(&copy).status().unwrap();
    assert!(status.success(), "codesign failed");
    copy
}

/// What `codesign --display` reports for `path`: its code directory
/// (flags included) and its entitlements.
#[cfg(target_os = "macos")]
fn signature_of(path: &std::path::Path) -> String {
    let out = std::process::Command::new("codesign")
        .args(["--display", "--verbose=2", "--entitlements", "-"])
        .arg(path)
        .output()
        .unwrap();
    assert!(out.status.success(), "codesign --display failed: {out:?}");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Whether the code directory's flags, as `codesign --display` prints them
/// (`flags=0x10002(adhoc,runtime)`), include the hardened runtime.
#[cfg(target_os = "macos")]
fn has_runtime_flag(signature: &str) -> bool {
    signature
        .lines()
        .filter(|l| l.starts_with("CodeDirectory "))
        .any(|l| {
            l.split_whitespace()
                .find_map(|w| w.strip_prefix("flags="))
                .is_some_and(|f| f.contains("runtime"))
        })
}

#[cfg(target_os = "macos")]
fn temp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ecsig")
        .tempdir_in("/tmp")
        .unwrap()
}

#[cfg(target_os = "macos")]
#[test]
fn hardened_runtime_flag_follows_the_signature() {
    let exe = std::env::current_exe().unwrap();
    assert!(
        run_child(&exe).contains("hardened_runtime=Some(false)"),
        "a linker-signed test binary has no hardened runtime"
    );

    let dir = temp_dir();
    let copy = runtime_signed_copy(dir.path(), "signed-copy", None);
    let signature = signature_of(&copy);
    assert!(has_runtime_flag(&signature), "{signature}");
    assert!(!signature.contains("get-task-allow"), "{signature}");
    let out = run_child(&copy);
    assert!(out.contains("hardened_runtime=Some(true)"), "{out}");
}

/// Gate 19 asks for the hardened runtime without `get-task-allow`. A
/// signature with both must not count as protected: the runtime flag alone
/// would be read as protection a debugger can bypass.
#[cfg(target_os = "macos")]
#[test]
fn get_task_allow_is_not_a_hardened_runtime() {
    let dir = temp_dir();
    let copy = runtime_signed_copy(dir.path(), "debuggable-copy", Some(GET_TASK_ALLOW));
    // Control: the signature has the runtime flag and the entitlement, so
    // only the get-task-allow check can make the report false.
    let signature = signature_of(&copy);
    assert!(has_runtime_flag(&signature), "{signature}");
    assert!(
        signature.contains("com.apple.security.get-task-allow"),
        "{signature}"
    );
    let out = run_child(&copy);
    assert!(out.contains("hardened_runtime=Some(false)"), "{out}");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn hardened_runtime_is_not_applicable() {
    assert_eq!(envcloak_sys::hardening_status().hardened_runtime, None);
}
