//! Process hardening applied to this test process (gate 19 building blocks).
//! It lowers the hard core limit for good, so it lives in its own binary.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use envcloak_sys::{
    core_dump_limit, disable_core_dumps, harden_process, hardening_report, hardening_status,
    lock_memory, set_non_dumpable, tracer_present,
};

#[test]
fn rlimit_core_is_zero_after_the_call() {
    disable_core_dumps().unwrap();
    assert_eq!(core_dump_limit().unwrap(), (0, 0));
    assert!(hardening_status().core_dumps_off);
}

#[test]
fn non_dumpable_after_the_call() {
    set_non_dumpable().unwrap();
    let h = hardening_status();
    if cfg!(target_os = "linux") {
        assert!(h.non_dumpable, "PR_GET_DUMPABLE must read 0");
    } else {
        assert!(!h.non_dumpable, "only Linux has a dumpable flag");
    }
}

#[test]
fn harden_process_reports_what_took_effect() {
    let h = harden_process();
    assert!(h.core_dumps_off);
    assert_eq!(h.non_dumpable, cfg!(target_os = "linux"));
    assert_eq!(h.hardened_runtime.is_some(), cfg!(target_os = "macos"));
    let report = hardening_report();
    assert!(report.contains("core_dumps_off=true\n"), "{report}");
    assert!(report.contains("rlimit_core=0/0\n"), "{report}");
    assert!(report.contains("tracer_present=false\n"), "{report}");
    // This binary keeps the system allocator.
    assert!(report.contains("wiping_allocator=false\n"), "{report}");
}

#[test]
fn lock_memory_locks_a_page() {
    let mut page = vec![0u8; 4096];
    lock_memory(&mut page).unwrap();
    lock_memory(&mut []).unwrap();
}

#[test]
fn tracer_present_survives_threads_coming_and_going() {
    // Linux lists /proc/self/task and reads each thread's status. A thread
    // that exits in between must be skipped, not turn the answer into an
    // error (its read fails with ENOENT or ESRCH).
    let stop = Arc::new(AtomicBool::new(false));
    let churn = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let threads: Vec<_> = (0..8).map(|_| std::thread::spawn(|| {})).collect();
                for t in threads {
                    t.join().unwrap();
                }
            }
        })
    };
    let mut errors = 0;
    for _ in 0..3000 {
        match tracer_present() {
            Ok(traced) => assert!(!traced),
            Err(_) => errors += 1,
        }
    }
    stop.store(true, Ordering::Relaxed);
    churn.join().unwrap();
    assert_eq!(errors, 0, "tracer_present failed while threads exited");
}
