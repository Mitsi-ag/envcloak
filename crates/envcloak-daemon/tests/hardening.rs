//! `envcloakd` installs the wiping allocator and hardens itself at start.
//! The full gate 19 check for the daemon comes with the daemon in T7.
#![allow(clippy::unwrap_used)]

use std::process::Command;

use envcloak_testkit::TestHome;

#[test]
fn daemon_reports_hardening_and_the_wiping_allocator() {
    let home = TestHome::new();
    let out = home
        .apply(&mut Command::new(env!("CARGO_BIN_EXE_envcloakd")))
        .args(["internal", "hardening"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let report = String::from_utf8(out.stdout).unwrap();
    assert!(report.contains("wiping_allocator=true\n"), "{report}");
    assert!(report.contains("core_dumps_off=true\n"), "{report}");
    assert!(report.contains("rlimit_core=0/0\n"), "{report}");
    if cfg!(target_os = "linux") {
        assert!(report.contains("non_dumpable=true\n"), "{report}");
    }
}
