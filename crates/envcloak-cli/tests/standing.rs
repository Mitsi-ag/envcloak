//! Standing approvals through the CLI (SPEC §10b "Standing approvals",
//! gate 40 sentence 3 and gate 26; M2 plan D-10 and M2-15):
//! - `envcloak approve <id> --standing 7d` creates a standing approval
//!   for a test-classified agent request and mints session grants for new
//!   sessions of that agent in the project without a prompt;
//! - `envcloak approve <id> --standing 7d` refuses a live or `unknown`
//!   binding before reading the passphrase (`Unread` FIFO);
//! - `envcloak standing ls` (`--json`), `envcloak status` (`--json`),
//!   `envcloak standing rm` (`--all`, `--agent`, `--project`, `<id>`) and
//!   `envcloak standing confirm` work end-to-end, including the full-vault
//!   rollback limit disclosure and sidecar reconciliation.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use common::{
    MANIFEST, cli, cli_command, daemon_exe, data_dir, finish_within, on_terminal_program,
    outside_dir, project, python3, run, run_on_terminal, secret_file, seed_vault, stderr, stdout,
};
use envcloak_core::SecretBytes;
use envcloak_core::audit::AuditKind;
use envcloak_core::vault::{LockedVault, VaultPaths};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels, testkit_bin,
};

struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    agent_bin: PathBuf,
    manifest: PathBuf,
    files: tempfile::TempDir,
    pass: PathBuf,
}

fn install_agent_binary(dest: &Path, identifier: &str) {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::copy(testkit_bin("fixture-agent"), dest).unwrap();
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/bin/codesign")
            .args(["-f", "-s", "-", "-i", identifier])
            .arg(dest)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    #[cfg(not(target_os = "macos"))]
    let _ = identifier;
}

fn start_standing_daemon(home: &TestHome) -> Daemon {
    let mut cmd = std::process::Command::new(daemon_exe());
    home.apply(&mut cmd);
    cmd.env(
        "ENVCLOAK_TEST_MAC_TEAM_IDS",
        "opencode=5NZ4Q7NXJ4,com.anthropic.claude-code=Q6L2SF6YDW",
    );
    if !cfg!(target_os = "macos") {
        cmd.env("ENVCLOAK_TEST_LINUX_STANDING", "1");
    }
    Daemon::start_command(cmd, &[])
}

impl Fixture {
    fn new() -> Self {
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);
        let agent_bin = home.home().join(".opencode/bin/opencode");
        install_agent_binary(&agent_bin, "opencode");
        let d = start_standing_daemon(&home);
        let files = outside_dir();
        let pass = secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let out = run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
        );
        assert!(out.status.success(), "{}{}", stderr(&out), d.log());
        let manifest = project(&home, "acme-web", MANIFEST).join("envcloak.toml");
        Fixture {
            cs,
            home,
            d,
            agent_bin,
            manifest,
            files,
            pass,
        }
    }

    fn person(&self, args: &[&str], pass: &Path) -> Output {
        let out = run_on_terminal(&self.home, args, &[(3, pass, true)]);
        self.swept(&out);
        out
    }

    fn agent(&self, args: &[&str]) -> Output {
        let mut argv: Vec<&Path> = vec![self.agent_bin.as_path(), Path::new("--"), cli()];
        argv.extend(args.iter().map(Path::new));
        let out = finish_within(
            on_terminal_program(&self.home, &argv, &[]),
            Duration::from_secs(60),
        );
        self.swept(&out);
        out
    }

    fn swept(&self, out: &Output) {
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

fn request_id(err: &str) -> String {
    let line = err
        .lines()
        .find(|l| l.contains("approval_required"))
        .unwrap_or_else(|| panic!("no approval_required in: {err}"));
    let id = line
        .split("request=")
        .nth(1)
        .and_then(|s| s.split(':').next())
        .unwrap_or_else(|| panic!("no request id in: {err}"));
    assert_eq!(id.len(), 8, "{line}");
    id.to_owned()
}

struct Unread {
    path: PathBuf,
    writer: std::thread::JoinHandle<std::fs::File>,
}

fn unread(dir: &Path, name: &str) -> Unread {
    let path = dir.join(name);
    let made = std::process::Command::new(python3())
        .args(["-c", "import os, sys\nos.mkfifo(sys.argv[1], 0o600)\n"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(made.success());
    let at = path.clone();
    let writer =
        std::thread::spawn(move || std::fs::OpenOptions::new().write(true).open(&at).unwrap());
    Unread { path, writer }
}

impl Unread {
    fn check(self) {
        let until = std::time::Instant::now() + Duration::from_secs(30);
        while !self.writer.is_finished() && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            self.writer.is_finished(),
            "the command never opened the descriptor"
        );
        drop(self.writer.join().unwrap());
    }
}

#[test]
fn standing_approval_refuses_live_and_unknown_without_reading_passphrase() {
    let f = Fixture::new();
    let m = f.manifest.to_str().unwrap();

    // Default profile binds live OPENAI_API_KEY and test STRIPE_SECRET_KEY.
    let out = f.agent(&["run", "--manifest", m, "--", "/usr/bin/true"]);
    assert_eq!(out.status.code(), Some(125));
    let id = request_id(&stderr(&out));

    let fifo = unread(f.files.path(), "unread-live");
    let out = f.person(
        &["approve", &id, "--standing", "7d", "--passphrase-fd", "3"],
        &fifo.path,
    );
    fifo.check();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("live_not_ticked"), "{}", stderr(&out));

    // Reclassify stripe/acme-web to unknown, then request only stripe/acme-web.
    let out = f.person(
        &[
            "items",
            "reclassify",
            "stripe/acme-web",
            "unknown",
            "--passphrase-fd",
            "3",
        ],
        &f.pass,
    );
    assert!(out.status.success(), "{}", stderr(&out));

    let proj2 = project(
        &f.home,
        "acme-unknown",
        "[project]\nname = \"acme-unknown\"\n\n[env]\nSTRIPE_SECRET_KEY = \"stripe/acme-web\"\n",
    );
    let m2 = proj2.join("envcloak.toml");
    let m2_str = m2.to_str().unwrap();
    let out = f.agent(&["run", "--manifest", m2_str, "--", "/usr/bin/true"]);
    assert_eq!(out.status.code(), Some(125));
    let id2 = request_id(&stderr(&out));

    let fifo2 = unread(f.files.path(), "unread-unknown");
    let out = f.person(
        &["approve", &id2, "--standing", "7d", "--passphrase-fd", "3"],
        &fifo2.path,
    );
    fifo2.check();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("invalid_options"), "{}", stderr(&out));

    f.sweep();
}

#[test]
fn standing_lifecycle_ls_rm_rollback_and_confirm() {
    let mut f = Fixture::new();
    let proj = project(
        &f.home,
        "acme-standing",
        "[project]\nname = \"acme-standing\"\n\n[env]\nSTRIPE_SECRET_KEY = \"stripe/acme-web\"\n",
    );
    let m = proj.join("envcloak.toml");
    let m_str = m.to_str().unwrap();

    // First agent session opens a pending request.
    let out = f.agent(&["run", "--manifest", m_str, "--", "/usr/bin/true"]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));
    let id = request_id(&stderr(&out));

    // Approve with `--standing 7d`.
    let out = f.person(
        &["approve", &id, "--standing", "7d", "--passphrase-fd", "3"],
        &f.pass,
    );
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert!(
        stdout(&out).contains(
            "session in this project, including one started by another program, gets these keys without asking"
        ),
        "{}",
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("standing approval "),
        "{}",
        stdout(&out)
    );

    // Second agent session runs without a prompt!
    let out = f.agent(&["run", "--manifest", m_str, "--", "/usr/bin/true"]);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));

    // A non-agent (unknown subject without a terminal) is not covered by the standing record.
    let out = run(
        &f.home,
        &["run", "--manifest", m_str, "--", "/usr/bin/true"],
        &[],
    );
    f.swept(&out);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));

    // `envcloak status` and `envcloak standing ls` report 1 standing approval in force.
    let out = run(&f.home, &["status"], &[]);
    f.swept(&out);
    assert!(out.status.success());
    assert!(
        stdout(&out).contains("standing approvals: 1 in force"),
        "{}",
        stdout(&out)
    );

    let out = run(&f.home, &["standing", "ls", "--json"], &[]);
    f.swept(&out);
    assert!(out.status.success());
    let listed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(listed["standing"].as_array().unwrap().len(), 1);
    let standing_id = listed["standing"][0]["id"].as_str().unwrap().to_owned();

    let out = run(&f.home, &["standing", "ls"], &[]);
    f.swept(&out);
    assert!(out.status.success());
    assert!(stdout(&out).contains(&standing_id), "{}", stdout(&out));

    // Snapshot the vault files before `standing rm` so we can simulate a rollback of vault.db alone.
    let vpaths = VaultPaths::under(data_dir(&f.home));
    let db_snap = std::fs::read(&vpaths.db).unwrap();
    let wal_path = vpaths.db.with_extension("db-wal");
    let wal_snap = std::fs::read(&wal_path).ok();

    // Revoke the standing approval and verify the rollback disclosure is printed.
    let out = run(&f.home, &["standing", "rm", &standing_id], &[]);
    f.swept(&out);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("Revoked 1 standing approval"),
        "{}",
        stdout(&out)
    );
    assert!(
        stdout(&out)
            .contains("restoring older copies of both the whole vault and <data>/policy-epoch"),
        "{}",
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("a program running as you can do so"),
        "{}",
        stdout(&out)
    );

    // Next agent session now prompts again.
    let out = f.agent(&["run", "--manifest", m_str, "--", "/usr/bin/true"]);
    assert_eq!(out.status.code(), Some(125), "{}", stderr(&out));

    // Stop the daemon, restore the old vault files while keeping the newer `<data>/policy-epoch`,
    // and restart the daemon.
    f.d.signal("-TERM");
    assert!(f.d.wait_exit(Duration::from_secs(30)).is_some());
    std::fs::write(&vpaths.db, &db_snap).unwrap();
    match &wal_snap {
        Some(w) => std::fs::write(&wal_path, w).unwrap(),
        None => {
            let _ = std::fs::remove_file(&wal_path);
        }
    }
    f.d = start_standing_daemon(&f.home);
    let out = f.person(&["unlock", "--passphrase-fd", "3"], &f.pass);
    assert!(out.status.success(), "{}", stderr(&out));

    // `status` and `standing ls` report `policy_epoch_unverified`, and agent run is refused.
    let out = run(&f.home, &["status"], &[]);
    f.swept(&out);
    assert!(
        stdout(&out).contains("policy_epoch_unverified"),
        "{}",
        stdout(&out)
    );

    let out = f.agent(&["run", "--manifest", m_str, "--", "/usr/bin/true"]);
    assert_ne!(out.status.code(), Some(0));
    assert!(
        stderr(&out).contains("policy_epoch_unverified"),
        "{}",
        stderr(&out)
    );

    // `standing confirm` without a terminal is refused before reading a passphrase.
    let fifo = unread(f.files.path(), "unread-confirm");
    let cmd = cli_command(
        &f.home,
        &["standing", "confirm", "--passphrase-fd", "3"],
        &[(3, &fifo.path, true)],
    );
    let out = finish_within(cmd, Duration::from_secs(60));
    fifo.check();
    f.swept(&out);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("proof_refused"), "{}", stderr(&out));

    // `standing confirm` on a terminal re-seals the sidecar and unpauses the standing record.
    let out = f.person(&["standing", "confirm", "--passphrase-fd", "3"], &f.pass);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert!(
        stdout(&out).contains("Confirmed 1 standing approval"),
        "{}",
        stdout(&out)
    );

    // Now the agent session runs without a prompt again!
    let out = f.agent(&["run", "--manifest", m_str, "--", "/usr/bin/true"]);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));

    // Check audit log entries for StandingCreate, StandingRevoke, StandingConfirm, StandingGrant.
    f.d.signal("-TERM");
    assert!(f.d.wait_exit(Duration::from_secs(30)).is_some());
    let v = LockedVault::open(&vpaths)
        .unwrap()
        .unlock_with_passphrase(&SecretBytes::copy_from(
            by_label(&f.cs, labels::VAULT_PASSPHRASE).value(),
        ))
        .map_err(|(_, e)| e)
        .unwrap();
    let (entries, _) = v.read_audit().unwrap();
    for kind in [
        AuditKind::StandingCreate,
        AuditKind::StandingGrant,
        AuditKind::StandingRevoke,
        AuditKind::StandingConfirm,
    ] {
        assert!(
            entries.iter().any(|e| e.record.kind == kind),
            "missing audit kind {kind:?}"
        );
    }

    f.sweep();
}
