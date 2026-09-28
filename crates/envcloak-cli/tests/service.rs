//! `envcloak daemon install` under the real service manager (SPEC §4.1,
//! T7 acceptance): launchd on macOS, the systemd user manager on Linux.
//! The daemon it starts answers the CLI, serves a vault, and stops on
//! `daemon uninstall`.
//!
//! It changes the user's service manager, so it runs only when
//! `ENVCLOAK_TEST_SERVICE_MANAGER=1` (CI sets it on both systems). It uses
//! its own label, so a real installation is never touched, and the test's
//! home, which the unit pins. On Linux, `systemctl --user` needs the user
//! manager's runtime directory: CI names it in
//! `ENVCLOAK_TEST_SERVICE_RUNTIME_DIR`, which the test passes on as
//! `XDG_RUNTIME_DIR` (the daemon's socket goes there too).
#![allow(clippy::unwrap_used)]

mod common;

use std::process::{Command, Output};
use std::time::{Duration, Instant};

use common::{cli_command, finish_within, outside_dir, secret_file, stderr, stdout};
use envcloak_testkit::{TestHome, by_label, canaries, fresh_seed, labels};

struct Installed<'a> {
    home: &'a TestHome,
    label: String,
}

impl Installed<'_> {
    fn cli(&self, args: &[&str], fds: &[common::Fd<'_>]) -> Output {
        let mut cmd = cli_command(self.home, args, fds);
        if let Some(dir) = std::env::var_os("ENVCLOAK_TEST_SERVICE_RUNTIME_DIR") {
            let dir = std::path::PathBuf::from(dir);
            cmd.env("XDG_RUNTIME_DIR", &dir).env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/bus", dir.display()),
            );
        }
        finish_within(cmd, Duration::from_secs(120))
    }
}

impl Drop for Installed<'_> {
    fn drop(&mut self) {
        let _ = self.cli(&["daemon", "uninstall", "--label", &self.label], &[]);
    }
}

fn parent_pid(pid: &str) -> String {
    let out = Command::new("ps")
        .args(["-o", "ppid=", "-p", pid])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn command_name(pid: &str) -> String {
    let out = Command::new("ps")
        .args(["-o", "comm=", "-p", pid])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
fn daemon_install_runs_envcloakd_under_the_service_manager() {
    if std::env::var_os("ENVCLOAK_TEST_SERVICE_MANAGER").is_none() {
        eprintln!("skipped: set ENVCLOAK_TEST_SERVICE_MANAGER=1 to load a test service");
        return;
    }
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let svc = Installed {
        home: &home,
        label: format!("ai.envcloak.test-{}", std::process::id()),
    };

    let out = svc.cli(&["daemon", "install", "--label", &svc.label], &[]);
    let said = stdout(&out);
    assert!(out.status.success(), "{said}{}", stderr(&out));
    let manager = if cfg!(target_os = "macos") {
        "launchd"
    } else {
        "systemd"
    };
    assert!(
        said.contains(&format!("envcloakd is running under {manager} (pid ")),
        "{said}"
    );
    let pid = said
        .split("(pid ")
        .nth(1)
        .and_then(|r| r.split(')').next())
        .unwrap()
        .to_owned();

    // Started by the service manager, not by the CLI.
    let parent = parent_pid(&pid);
    if cfg!(target_os = "macos") {
        assert_eq!(parent, "1", "launchd is the daemon's parent");
    } else {
        assert!(
            command_name(&parent).contains("systemd"),
            "{}",
            command_name(&parent)
        );
    }

    let status = svc.cli(&["status"], &[]);
    assert!(
        stdout(&status).contains(&format!("daemon: running (pid {pid}")),
        "{}",
        stdout(&status)
    );

    // It serves a vault.
    let files = outside_dir();
    let pass = secret_file(
        files.path(),
        "pass",
        by_label(&cs, labels::VAULT_PASSPHRASE).value(),
    );
    let kit = files.path().join("kit");
    let create = svc.cli(
        &[
            "vault",
            "create",
            "--passphrase-fd",
            "3",
            "--kit-fd",
            "4",
            "--kdf-memory",
            "64MiB",
        ],
        &[(3, &pass, true), (4, &kit, false)],
    );
    assert!(create.status.success(), "{}", stderr(&create));
    assert!(stdout(&svc.cli(&["status"], &[])).contains("vault: unlocked"));

    // Uninstalling stops it; the vault stays.
    let out = svc.cli(&["daemon", "uninstall", "--label", &svc.label], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        let s = svc.cli(&["status"], &[]);
        if stdout(&s).contains("daemon: not running") {
            break;
        }
        assert!(
            Instant::now() < end,
            "the daemon is still running: {}",
            stdout(&s)
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    if cfg!(target_os = "macos") {
        assert!(
            !home
                .home()
                .join(format!("Library/LaunchAgents/{}.plist", svc.label))
                .exists()
        );
    }
}
