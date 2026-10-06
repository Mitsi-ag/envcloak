//! The probes' children stay this process's own until it waits for them,
//! whatever SIGCHLD setup `envcloak` was started with (the verifier's
//! review of M2-28): a parent that leaves SIGCHLD ignored, or set with
//! `SA_NOCLDWAIT`, would otherwise have the kernel reap each child the
//! moment it exits, its pid and process group free for another process
//! while the probes still signal them by number.
//!
//! One test in its own binary: it changes this process's signal table.
//!
//! Mutation checked: `detect::spawn_unreaped` without its
//! `keep_children_unreaped` call: the kernel reaps the children on its
//! own, `has_exited` and the wait answer `ECHILD`, the version is
//! `not_recognized` and the session's status is lost, and this fails.

#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use envcloak_agents::detect;
use envcloak_agents::hook::Host;
use envcloak_agents::probe::HostSession;
use envcloak_sys::testing::{ChildReaping, set_sigchld, sigchld_setup};

#[test]
fn children_stay_unreaped_with_sigchld_ignored_or_no_wait() {
    for how in [ChildReaping::Ignored, ChildReaping::NoWait] {
        set_sigchld(how).unwrap_or_else(|e| panic!("{e}"));
        let (ignored, no_wait) = sigchld_setup();
        assert!(ignored || no_wait, "{how:?} was not set");

        // The host detection's `--version`.
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let fake = dir.path().join("claude");
        std::fs::write(&fake, "#!/bin/sh\necho '2.1.280 (Claude Code)'\n")
            .unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("{e}"));
        let vars = [(OsString::from("HOME"), dir.path().as_os_str().to_owned())];
        let got = detect::detect_identified(Host::ClaudeCode, dir.path().as_os_str(), &vars);
        assert_eq!(
            got.map(|(d, _)| d.version),
            Ok("2.1.280".to_owned()),
            "{how:?}: the version's child was reaped behind the wait"
        );
        assert_eq!(sigchld_setup(), (false, false), "{how:?}: still reaping");

        // A host session: its exit is seen, unreaped, and its status read.
        set_sigchld(how).unwrap_or_else(|e| panic!("{e}"));
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "exit 7"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut session = HostSession::spawn(cmd).unwrap_or_else(|e| panic!("{e}"));
        let pid = i32::try_from(session.child.id()).unwrap_or(0);
        let end = Instant::now() + Duration::from_secs(20);
        let seen = loop {
            match envcloak_sys::has_exited(pid) {
                Ok(true) => break Ok(()),
                Ok(false) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)),
                Ok(false) => break Err("did not exit".to_owned()),
                Err(e) => break Err(format!("not this process's child any more: {e}")),
            }
        };
        assert_eq!(seen, Ok(()), "{how:?}");
        let status = session.child.wait().map(|s| s.code());
        assert_eq!(status.ok(), Some(Some(7)), "{how:?}");
        session.hang_up();
    }
}
