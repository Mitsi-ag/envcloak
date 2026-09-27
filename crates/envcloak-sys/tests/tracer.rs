//! `tracer_present` against a real tracer. A child copy of this binary is
//! traced by its parent (this process) and reports what it sees:
//!
//! - main thread: the child asks to be traced (`PTRACE_TRACEME`);
//! - Linux, another thread: the parent attaches to one helper thread of
//!   the child only. `/proc/self/status` shows only the main thread's
//!   tracer, so this fails if detection ever reads that file alone.
//!
//! This binary has no libtest harness (`harness = false`), so the child
//! calls `PTRACE_TRACEME` on its main thread. From a libtest worker thread
//! it would hang on Linux: when a traced non-leader thread exits it stays a
//! zombie until its tracer reaps it with `__WALL`, and until then the
//! process never finishes exiting. The helper-thread check detaches before
//! the child exits for the same reason.
#![allow(clippy::unwrap_used)]

use std::process::Command;

use envcloak_sys::tracer_present;

const CHILD_ENV: &str = "ENVCLOAK_SYS_TRACER_CHILD";

fn main() {
    match std::env::var(CHILD_ENV).as_deref() {
        Ok("main") => return main_thread_child(),
        #[cfg(target_os = "linux")]
        Ok("thread") => return other_thread_child(),
        _ => {}
    }

    assert!(!tracer_present().unwrap(), "no tracer expected");
    main_thread_check();
    #[cfg(target_os = "linux")]
    other_thread_check();
    println!("tracer: untraced and traced checks passed");
}

fn main_thread_child() {
    let before = tracer_present().unwrap();
    envcloak_sys::testing::trace_me().unwrap();
    let after = tracer_present().unwrap();
    println!("before={before} after={after}");
}

fn main_thread_check() {
    let out = Command::new(std::env::current_exe().unwrap())
        .env(CHILD_ENV, "main")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "child failed: {out:?}");
    assert!(
        stdout.contains("before=false after=true"),
        "child output: {stdout}"
    );
}

/// Reports a helper thread's id, waits until the parent has attached to
/// that thread, then reports what the main thread sees.
#[cfg(target_os = "linux")]
fn other_thread_child() {
    use std::io::BufRead;

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tx.send(envcloak_sys::testing::current_tid()).unwrap();
        loop {
            std::thread::park();
        }
    });
    let tid = rx.recv().unwrap();
    let before = tracer_present().unwrap();
    println!("tid={tid} before={before}");
    let mut stdin = std::io::stdin().lock();
    let mut line = String::new();
    if stdin.read_line(&mut line).unwrap() == 0 {
        return;
    }
    println!("after={}", tracer_present().unwrap());
    // Wait until the parent has detached and closed stdin.
    while stdin.read_line(&mut line).is_ok_and(|n| n > 0) {}
}

#[cfg(target_os = "linux")]
fn other_thread_check() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::Stdio;

    use envcloak_sys::testing::{attach, detach};

    let mut child = Command::new(std::env::current_exe().unwrap())
        .env(CHILD_ENV, "thread")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

    let first = lines.next().unwrap().unwrap();
    let (tid, before) = first
        .strip_prefix("tid=")
        .and_then(|r| r.split_once(" before="))
        .unwrap();
    let tid: i32 = tid.parse().unwrap();
    assert_eq!(before, "false", "{first}");

    attach(tid).expect("attach to the child's helper thread");
    writeln!(stdin, "attached").unwrap();
    let second = lines.next().unwrap().unwrap();
    detach(tid).expect("detach from the helper thread");
    drop(stdin);
    assert!(child.wait().unwrap().success());
    assert_eq!(
        second, "after=true",
        "a tracer on a non-main thread must be detected"
    );
}
