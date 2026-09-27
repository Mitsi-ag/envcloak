//! `tracer_present` against a real tracer: a child copy of this binary asks
//! to be traced by its parent (this process) and reports what it sees.
//!
//! This binary has no libtest harness (`harness = false`), so the child
//! calls `PTRACE_TRACEME` on its main thread. From a libtest worker thread
//! it would hang on Linux: when a traced non-leader thread exits it stays a
//! zombie until its tracer reaps it with `__WALL`, and until then the
//! process never finishes exiting.
#![allow(clippy::unwrap_used)]

use std::process::Command;

use envcloak_sys::tracer_present;

const CHILD_ENV: &str = "ENVCLOAK_SYS_TRACER_CHILD";

fn main() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let before = tracer_present().unwrap();
        envcloak_sys::testing::trace_me().unwrap();
        let after = tracer_present().unwrap();
        println!("before={before} after={after}");
        return;
    }

    assert!(!tracer_present().unwrap(), "no tracer expected");

    let out = Command::new(std::env::current_exe().unwrap())
        .env(CHILD_ENV, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "child failed: {out:?}");
    assert!(
        stdout.contains("before=false after=true"),
        "child output: {stdout}"
    );
    println!("tracer: untraced and traced checks passed");
}
