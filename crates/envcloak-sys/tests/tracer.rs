//! `tracer_present` against a real tracer: a child copy of this test binary
//! asks to be traced by its parent (this process) and reports what it sees.
#![allow(clippy::unwrap_used)]

use std::process::Command;

use envcloak_sys::tracer_present;

const CHILD_ENV: &str = "ENVCLOAK_SYS_TRACER_CHILD";

#[test]
fn untraced_process_reports_no_tracer() {
    assert!(!tracer_present().unwrap());
}

/// Runs only as the child of `traced_process_reports_a_tracer`.
#[test]
fn traced_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let before = tracer_present().unwrap();
    envcloak_sys::testing::trace_me().unwrap();
    let after = tracer_present().unwrap();
    println!("before={before} after={after}");
}

#[test]
fn traced_process_reports_a_tracer() {
    let exe = std::env::current_exe().unwrap();
    let out = Command::new(exe)
        .args(["--exact", "traced_child", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "child failed: {out:?}");
    assert!(
        stdout.contains("before=false after=true"),
        "child output: {stdout}"
    );
}
