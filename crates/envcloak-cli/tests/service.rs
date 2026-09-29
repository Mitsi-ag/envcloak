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
//!
//! Gate 12: every stream the CLI printed is swept as soon as it is
//! captured, before anything can show it, and so is the log the service
//! manager kept of the daemon (launchd's log file in the test home on
//! macOS, the user unit's journal on Linux), after the test has checked
//! it holds the daemon's own lines.
#![allow(clippy::unwrap_used)]

mod common;

use std::process::{Command, Output};
use std::time::{Duration, Instant};

use common::{cli_command, finish_within, outside_dir, secret_file, stderr, stdout};
use envcloak_testkit::{
    Canary, TestHome, assert_no_canary, assert_sweep_clean, by_label, canaries, fresh_seed, labels,
};

struct Installed<'a> {
    home: &'a TestHome,
    label: String,
    /// The fixture secrets, swept for in everything captured.
    cs: Vec<Canary>,
}

impl Installed<'_> {
    /// Runs `envcloak <args>`, and sweeps both streams before returning
    /// them, so no failure message can show a value.
    fn cli(&self, args: &[&str], fds: &[common::Fd<'_>]) -> Output {
        let out = self.run(args, fds);
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
        out
    }

    /// Runs `envcloak <args>` with the service manager's runtime directory.
    fn run(&self, args: &[&str], fds: &[common::Fd<'_>]) -> Output {
        let mut cmd = cli_command(self.home, args, fds);
        if let Some(dir) = runtime_dir() {
            cmd.env("XDG_RUNTIME_DIR", &dir);
            if dir.join("bus").exists() {
                cmd.env(
                    "DBUS_SESSION_BUS_ADDRESS",
                    format!("unix:path={}/bus", dir.display()),
                );
            }
        }
        finish_within(cmd, Duration::from_secs(120))
    }

    /// What the service manager kept of the daemon's standard output and
    /// error: launchd's log file on macOS, the unit's journal on Linux.
    /// Waits up to 20 seconds for it to hold the daemon's `listening`
    /// line (the journal can lag), which shows it is the right log;
    /// fails otherwise, since a log that cannot be read cannot be swept.
    fn daemon_log(&self) -> Vec<u8> {
        let end = Instant::now() + Duration::from_secs(20);
        loop {
            let log = self.read_daemon_log();
            let found = log.windows(20).any(|w| w == b"envcloakd: listening");
            if found || Instant::now() >= end {
                assert_no_canary(&log, &self.cs);
                assert!(
                    found,
                    "the service manager's log of the daemon ({} bytes) has no listening line",
                    log.len()
                );
                return log;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    #[cfg(target_os = "macos")]
    fn read_daemon_log(&self) -> Vec<u8> {
        std::fs::read(self.home.home().join("Library/Logs/EnvCloak/envcloakd.log"))
            .unwrap_or_default()
    }

    /// The user unit's journal: the user's own journal first, then the
    /// system journal (readable to the `adm` and `systemd-journal`
    /// groups), then the system journal through `sudo -n` (CI has it).
    #[cfg(not(target_os = "macos"))]
    fn read_daemon_log(&self) -> Vec<u8> {
        let unit = format!("{}.service", self.label);
        let user_unit = format!("_SYSTEMD_USER_UNIT={unit}");
        let tries: [&[&str]; 3] = [
            &["journalctl", "--user", "-u", &unit],
            &["journalctl", &user_unit],
            &["sudo", "-n", "journalctl", &user_unit],
        ];
        let mut best = Vec::new();
        for argv in tries {
            let mut cmd = Command::new(argv[0]);
            cmd.args(&argv[1..]).args(["-o", "cat", "--no-pager"]);
            if let Some(dir) = runtime_dir() {
                cmd.env("XDG_RUNTIME_DIR", dir);
            }
            let Ok(out) = cmd.output() else { continue };
            if out.stdout.len() > best.len() {
                best = out.stdout;
            }
        }
        best
    }
}

impl Drop for Installed<'_> {
    fn drop(&mut self) {
        // Nothing is shown, so nothing is swept: a panic here, while a
        // failed test unwinds, would abort the run.
        let _ = self.run(&["daemon", "uninstall", "--label", &self.label], &[]);
    }
}

/// The user manager's runtime directory CI names.
fn runtime_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("ENVCLOAK_TEST_SERVICE_RUNTIME_DIR").map(std::path::PathBuf::from)
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
    let home = TestHome::new();
    let mut svc = Installed {
        home: &home,
        label: format!("ai.envcloak.test-{}", std::process::id()),
        cs: canaries(fresh_seed()),
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

    // It serves a vault. The Recovery Kit is a secret too.
    let files = outside_dir();
    let pass = secret_file(
        files.path(),
        "pass",
        by_label(&svc.cs, labels::VAULT_PASSPHRASE).value(),
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
    let kit_text = std::fs::read_to_string(&kit).unwrap();
    svc.cs
        .push(Canary::new("RECOVERY_KIT", kit_text.trim_end().to_owned()));
    for o in [&out, &status, &create] {
        assert_no_canary(&o.stdout, &svc.cs);
        assert_no_canary(&o.stderr, &svc.cs);
    }
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

    // The daemon's whole log, as the service manager kept it, and
    // everything in the home.
    svc.daemon_log();
    assert_sweep_clean(home.root(), &svc.cs);
}
