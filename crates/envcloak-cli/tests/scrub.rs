//! Gate 37 against the CLI and daemon in an isolated HOME.
#![allow(clippy::unwrap_used)]
mod common;
use common::*;
use envcloak_testkit::{TestHome, by_label, canaries, fresh_seed, labels};
use serde_json::Value;
use std::path::Path;
use std::time::{Duration, SystemTime};

fn age(path: &Path) {
    let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.set_times(
        std::fs::FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(300)),
    )
    .unwrap();
}
#[test]
fn gate37_cli_rewrites_marks_and_undoes_with_one_proof() {
    let home = TestHome::new();
    let values = canaries(fresh_seed());
    seed_vault(&home, &values);
    let _daemon = start_daemon(&home);
    let outside = outside_dir();
    let pass = secret_file(
        outside.path(),
        "pass",
        by_label(&values, labels::VAULT_PASSPHRASE).value(),
    );
    assert!(
        run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)]
        )
        .status
        .success()
    );
    let path = home.home().join(".claude/projects/fixture/events.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let value = by_label(&values, labels::OPENAI_API_KEY).as_str();
    let original = format!("{}\n", serde_json::json!({"text": [value, value]}));
    std::fs::write(&path, &original).unwrap();
    age(&path);
    let out = run_on_terminal(
        &home,
        &["scrub", "--path", path.to_str().unwrap(), "--yes", "--json"],
        &[],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["files"][0]["state"], "scrubbed");
    let backup = report["files"][0]["backup"].as_str().unwrap();
    let after = std::fs::read(&path).unwrap();
    assert!(!after.windows(value.len()).any(|w| w == value.as_bytes()));
    serde_json::from_slice::<Value>(&after).unwrap();
    let show = run(&home, &["show", "openai/acme-web", "--json"], &[]);
    let shown: Value = serde_json::from_slice(&show.stdout).unwrap();
    assert!(!shown["exposed"].is_null());
    let outside = outside_dir();
    let pass = secret_file(
        outside.path(),
        "pass",
        by_label(&values, labels::VAULT_PASSPHRASE).value(),
    );
    let undo = run_on_terminal(
        &home,
        &["scrub", "--undo", backup, "--passphrase-fd", "3", "--json"],
        &[(3, &pass, true)],
    );
    assert!(undo.status.success(), "{}", stderr(&undo));
    assert!(std::fs::read(&path).unwrap() == original.as_bytes());
}

struct Fixture {
    home: TestHome,
    daemon: envcloak_testkit::Daemon,
    values: Vec<envcloak_testkit::Canary>,
    _outside: tempfile::TempDir,
    pass: std::path::PathBuf,
    path: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let home = TestHome::new();
        let values = canaries(fresh_seed());
        seed_vault(&home, &values);
        let mut command = std::process::Command::new(daemon_exe());
        home.apply(&mut command)
            .env(envcloak_sys::testing::TRACE, "1");
        let daemon = envcloak_testkit::Daemon::start_command(command, &[]);
        let outside = outside_dir();
        let pass = secret_file(
            outside.path(),
            "pass",
            by_label(&values, labels::VAULT_PASSPHRASE).value(),
        );
        assert!(
            run_on_terminal(
                &home,
                &["unlock", "--passphrase-fd", "3"],
                &[(3, &pass, true)]
            )
            .status
            .success()
        );
        let path = home.home().join(".claude/projects/scrub/events.jsonl");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let f = Self {
            home,
            daemon,
            values,
            _outside: outside,
            pass,
            path,
        };
        f.write();
        f
    }
    fn write(&self) {
        let value = by_label(&self.values, labels::OPENAI_API_KEY).as_str();
        let short = by_label(&self.values, labels::SHORT_TOKEN).as_str();
        let body = serde_json::json!({"text":[value,short,format!("postgres://person:{short}@db.local/name")]});
        std::fs::write(&self.path, format!("{body}\n")).unwrap();
        age(&self.path);
    }
    fn scrub(&self, agent: bool) -> std::process::Output {
        let mut cmd = on_terminal_command(
            &self.home,
            &[
                "scrub",
                "--path",
                self.path.to_str().unwrap(),
                "--yes",
                "--json",
            ],
            &[],
        );
        if agent {
            cmd.env("ENVCLOAK_FIXTURE_AGENT", "1");
        }
        finish_within(cmd, Duration::from_secs(900))
    }
    fn undo(&self, id: &str, extra: &[&str]) -> std::process::Output {
        let mut args = vec!["scrub", "--undo", id, "--passphrase-fd", "3", "--json"];
        args.extend_from_slice(extra);
        finish_within(
            on_terminal_command(&self.home, &args, &[(3, &self.pass, true)]),
            Duration::from_secs(900),
        )
    }
}
fn backup(out: &std::process::Output) -> String {
    assert!(out.status.success(), "{} {}", stderr(out), stdout(out));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    v["files"][0]["backup"].as_str().unwrap().into()
}
#[test]
fn gate37_catalog_formats_survive_file_and_directory_selection() {
    let f = Fixture::new();
    std::fs::remove_file(&f.path).unwrap();
    let value = by_label(&f.values, labels::OPENAI_API_KEY).as_str();
    let cases = [
        (".claude/paste-cache/paste.txt", false),
        (".claude/file-history/snapshot.json", false),
        (".claude/projects/tool-output.json", false),
        (".codex/log/session.log", false),
        (".codex/sessions/session", true),
        (".claude/projects/session.jsonl", true),
    ];
    for selection in ["catalog", "directory", "file"] {
        for (relative, jsonl) in cases {
            let path = f.home.home().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let original = if jsonl {
                format!(
                    "{}\n{}\n",
                    serde_json::json!({"text":value}),
                    serde_json::json!({"text":value})
                )
            } else {
                format!("pasted {value} here\n")
            };
            std::fs::write(&path, &original).unwrap();
            age(&path);
            let selected = if selection == "directory" {
                path.parent().unwrap()
            } else {
                &path
            };
            let mut args = vec!["scrub", "--yes", "--json"];
            if selection != "catalog" {
                args.extend(["--path", selected.to_str().unwrap()]);
            }
            let mut cmd = on_terminal_command(&f.home, &args, &[]);
            cmd.env("CLAUDE_CODE_TMPDIR", f.home.root().join("tmp"));
            let out = finish_within(cmd, Duration::from_secs(180));
            assert!(
                out.status.success(),
                "{selection} {relative}: {} {}",
                stderr(&out),
                stdout(&out)
            );
            let id = backup(&out);
            let after = std::fs::read(&path).unwrap();
            envcloak_testkit::assert_no_canary(&after, &f.values);
            if jsonl {
                assert_eq!(
                    after
                        .split(|b| *b == b'\n')
                        .filter(|s| !s.is_empty())
                        .count(),
                    2
                );
                for line in after.split(|b| *b == b'\n').filter(|s| !s.is_empty()) {
                    serde_json::from_slice::<Value>(line).unwrap();
                }
            } else {
                assert_eq!(after, b"pasted [envcloak:redacted:openai/acme-web] here\n");
            }
            let undone = f.undo(&id, &[]);
            assert!(undone.status.success(), "{}", stderr(&undone));
            assert!(std::fs::read(&path).unwrap() == original.as_bytes());
            std::fs::remove_file(path).unwrap();
        }
    }
}
#[test]
fn gate37_short_values_untouched_output_swept_and_later_edits_refuse_undo() {
    let mut f = Fixture::new();
    let out = f.scrub(false);
    let id = backup(&out);
    envcloak_testkit::assert_no_canary(&out.stdout, &f.values);
    envcloak_testkit::assert_no_canary(&out.stderr, &f.values);
    let after = std::fs::read(&f.path).unwrap();
    let short = by_label(&f.values, labels::SHORT_TOKEN).value();
    assert_eq!(
        after.windows(short.len()).filter(|w| *w == short).count(),
        2,
        "short value rewritten"
    );
    assert!(stdout(&out).contains("Short values are neither found nor scrubbed"));
    assert!(!stdout(&out).contains("except registry-recognized"));
    let docs = include_str!("../../../docs/DOCTOR.md");
    assert!(docs.contains("Values under 16 characters are never found or scrubbed"));
    std::fs::write(&f.path, b"later edit\n").unwrap();
    let undo = f.undo(&id, &[]);
    assert!(!undo.status.success());
    assert!(stdout(&undo).contains("edited_since"));
    assert!(std::fs::read(&f.path).unwrap() == b"later edit\n");
    f.daemon.signal("-TERM");
    assert!(f.daemon.wait_exit(Duration::from_secs(30)).is_some());
    let vault = envcloak_core::vault::LockedVault::open(&envcloak_core::vault::VaultPaths::under(
        data_dir(&f.home),
    ))
    .unwrap()
    .unlock_with_passphrase(&envcloak_core::SecretBytes::copy_from(
        by_label(&f.values, labels::VAULT_PASSPHRASE).value(),
    ))
    .map_err(|(_, e)| e)
    .unwrap();
    let (audit, _) = vault.read_audit().unwrap();
    let scans: Vec<_> = audit
        .iter()
        .filter(|e| e.record.kind == envcloak_core::audit::AuditKind::ScanMatch)
        .collect();
    assert_eq!(
        scans.len(),
        3,
        "display, confirmation and publication compare again"
    );
    for e in scans {
        assert_eq!(e.record.decision.reason.as_deref(), Some("scrub"));
        assert!(
            e.record
                .decision
                .counts
                .iter()
                .any(|(name, count)| name == "compared_guessable" && *count == 0)
        );
    }
}
#[test]
fn gate37_agent_backup_requires_explicit_creator_tick() {
    let f = Fixture::new();
    let before = std::fs::read(&f.path).unwrap();
    let id = backup(&f.scrub(true));
    let denied = f.undo(&id, &[]);
    assert!(!denied.status.success());
    assert!(stderr(&denied).contains("created_by_agent"));
    assert!(stderr(&denied).contains("not by you"));
    let allowed = f.undo(&id, &["--created-by-agent"]);
    assert!(allowed.status.success(), "{}", stderr(&allowed));
    assert!(std::fs::read(&f.path).unwrap() == before);
}
struct Owned(std::process::Child);
impl Drop for Owned {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn paused(f: &Fixture, at: usize) -> (Owned, tempfile::TempDir) {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    for i in 0..at {
        std::fs::write(d.path().join(format!("{i:03}.go")), b"go").unwrap();
    }
    let mut cmd = cli_command(
        &f.home,
        &[
            "scrub",
            "--path",
            f.path.to_str().unwrap(),
            "--yes",
            "--json",
        ],
        &[],
    );
    cmd.env("ENVCLOAK_TEST_PAUSE_DIR", d.path());
    let mut child = Owned(cmd.spawn().unwrap());
    let until = std::time::Instant::now() + Duration::from_secs(180);
    loop {
        if std::fs::read_dir(d.path()).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&format!("{at:03}.scrub_"))
        }) {
            break;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "scrub exited before pause"
        );
        assert!(std::time::Instant::now() < until, "scrub pause timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
    (child, d)
}
#[test]
fn gate37_kill_at_every_pause_leaves_whole_files_and_no_temporary_exposure() {
    let f = Fixture::new();
    let value = by_label(&f.values, labels::OPENAI_API_KEY).value();
    let mut original_count = 0;
    let mut scrubbed_count = 0;
    for at in 0..6 {
        f.write();
        let before = std::fs::read(&f.path).unwrap();
        let (mut child, _pause) = paused(&f, at);
        // The detector's positive control is the intentionally exposed input.
        if at < 4 {
            assert!(
                std::fs::read(&f.path)
                    .unwrap()
                    .windows(value.len())
                    .any(|w| w == value)
            );
        }
        for e in std::fs::read_dir(f.path.parent().unwrap()).unwrap() {
            let p = e.unwrap().path();
            if p == f.path {
                continue;
            }
            let bytes = std::fs::read(p).unwrap();
            assert!(
                !bytes.windows(value.len()).any(|w| w == value),
                "plaintext temporary file"
            );
        }
        assert!(
            envcloak_testkit::sweep_dir(&data_dir(&f.home).join("backups"), &f.values).is_empty(),
            "encrypted-backup exposure detected"
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let bytes = std::fs::read(&f.path).unwrap();
        if bytes == before {
            original_count += 1;
        } else {
            scrubbed_count += 1;
            assert!(!bytes.windows(value.len()).any(|w| w == value));
            serde_json::from_slice::<Value>(&bytes).unwrap();
            let shown = run(&f.home, &["show", "openai/acme-web", "--json"], &[]);
            let item: Value = serde_json::from_slice(&shown.stdout).unwrap();
            assert!(
                !item["exposed"].is_null(),
                "crash left scrubbed item unflagged"
            );
        }
        // Remove only known scrubbed fixture leftovers before the next case.
        for e in std::fs::read_dir(f.path.parent().unwrap()).unwrap() {
            let p = e.unwrap().path();
            if p != f.path {
                std::fs::remove_file(p).unwrap();
            }
        }
    }
    assert_eq!(original_count, 4);
    assert_eq!(scrubbed_count, 2);
}
#[test]
fn gate37_recent_live_writer_symlink_and_failed_backup_never_succeed() {
    let f = Fixture::new();
    // A live append loop pauses after closing its descriptor. Even in that
    // gap it must be refused by age, independently of open-file detection.
    let mut writer = std::process::Command::new("/usr/bin/python3");
    f.home
        .apply(&mut writer)
        .args([
            "-I",
            "-B",
            "-c",
            r#"
import sys,time
for i in range(3):
    with open(sys.argv[1],'ab') as f: f.write(b'\n')
    time.sleep(.05)
print('closed',flush=True)
sys.stdin.readline()
"#,
        ])
        .arg(&f.path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut writer = Owned(writer.spawn().unwrap());
    use std::io::BufRead;
    let mut line = String::new();
    std::io::BufReader::new(writer.0.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "closed\n");
    let out = f.scrub(false);
    assert!(!out.status.success());
    assert!(stdout(&out).contains("recently_changed"));
    writer.0.stdin.take();
    writer.0.wait().unwrap();
    let original = std::fs::read(&f.path).unwrap();
    let target = f.path.with_extension("held");
    std::fs::rename(&f.path, &target).unwrap();
    std::os::unix::fs::symlink(&target, &f.path).unwrap();
    let out = f.scrub(false);
    assert!(!out.status.success());
    assert!(stdout(&out).contains("symlink"));
    assert!(std::fs::read(&target).unwrap() == original);
    std::fs::remove_file(&f.path).unwrap();
    std::fs::rename(&target, &f.path).unwrap();
    age(&f.path);
    let backups = data_dir(&f.home).join("backups");
    std::fs::create_dir_all(&backups).unwrap();
    let held = backups.with_file_name("held-backups");
    std::fs::rename(&backups, &held).unwrap();
    std::fs::write(&backups, b"fixture obstruction").unwrap();
    let out = f.scrub(false);
    std::fs::remove_file(&backups).unwrap();
    std::fs::rename(&held, &backups).unwrap();
    assert!(!out.status.success());
    assert!(std::fs::read(&f.path).unwrap() == original);
}

#[test]
fn gate37_scrub_backup_retention_is_seven_days_by_an_independent_clock() {
    let f = Fixture::new();
    let id = backup(&f.scrub(false));
    let paths = envcloak_core::vault::VaultPaths::under(data_dir(&f.home));
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Literal contract duration, deliberately independent of the implementation constant.
    let before = envcloak_core::file_backup_v2::list_file_backups_v2(&paths).unwrap();
    assert!(before.iter().any(|b| b.id.to_string() == id));
    envcloak_core::file_backup_v2::purge_file_backups_v2(&paths, now + 6 * 24 * 3600).unwrap();
    assert!(
        envcloak_core::file_backup_v2::list_file_backups_v2(&paths)
            .unwrap()
            .iter()
            .any(|b| b.id.to_string() == id)
    );
    envcloak_core::file_backup_v2::purge_file_backups_v2(&paths, now + 7 * 24 * 3600 + 1).unwrap();
    assert!(
        !envcloak_core::file_backup_v2::list_file_backups_v2(&paths)
            .unwrap()
            .iter()
            .any(|b| b.id.to_string() == id)
    );
}
#[test]
fn gate37_256_mib_undo_uses_one_argon2id_run_and_restores_exact_digest() {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    let f = Fixture::new();
    // One small JSONL value followed by bounded scalar lines, totaling 256 MiB.
    let original = std::fs::read(&f.path).unwrap();
    let mut file = std::fs::File::options().append(true).open(&f.path).unwrap();
    let mut chunk = vec![b' '; 512 * 1024];
    for i in (0..chunk.len()).step_by(8192) {
        chunk[i] = b'0';
    }
    for i in (8191..chunk.len()).step_by(8192) {
        chunk[i] = b'\n';
    }
    let mut left = 256 * 1024 * 1024 - original.len();
    let mut hash = Sha256::new();
    hash.update(&original);
    while left > 0 {
        let n = left.min(chunk.len());
        file.write_all(&chunk[..n]).unwrap();
        hash.update(&chunk[..n]);
        left -= n;
    }
    drop(file);
    age(&f.path);
    let id = backup(&f.scrub(false));
    let before = f
        .daemon
        .log()
        .matches("envcloak test: argon2id run")
        .count();
    let undo = f.undo(&id, &[]);
    assert!(undo.status.success(), "{}", stderr(&undo));
    let log = f.daemon.log_when(Duration::from_secs(5), |s| {
        s.matches("envcloak test: argon2id run").count() > before
    });
    assert_eq!(
        log.matches("envcloak test: argon2id run").count() - before,
        1,
        "one restore proof must run Argon2id once"
    );
    assert_eq!(
        envcloak_scan::scrub::current_digest(&f.path).unwrap(),
        <[u8; 32]>::from(hash.finalize())
    );
}

fn finish(mut child: Owned, pause: &Path, at: usize) -> std::process::Output {
    use std::io::Read;
    for next in at..6 {
        std::fs::write(pause.join(format!("{next:03}.go")), b"go").unwrap();
    }
    let until = std::time::Instant::now() + Duration::from_secs(180);
    let status = loop {
        if let Some(s) = child.0.try_wait().unwrap() {
            break s;
        }
        assert!(std::time::Instant::now() < until, "scrub did not exit");
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    std::process::Output {
        status,
        stdout,
        stderr,
    }
}
#[test]
fn gate37_failed_result_record_never_reports_success_and_unrecorded_needs_ack() {
    let f = Fixture::new();
    let before = std::fs::read(&f.path).unwrap();
    let (child, pause) = paused(&f, 5);
    assert!(run(&f.home, &["lock"], &[]).status.success());
    let out = finish(child, pause.path(), 5);
    assert!(!out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["files"][0]["state"], "refused");
    let id = report["files"][0]["backup"].as_str().unwrap();
    assert!(
        run_on_terminal(
            &f.home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &f.pass, true)]
        )
        .status
        .success()
    );
    let denied = f.undo(id, &["--created-by-agent"]);
    assert!(!denied.status.success());
    assert!(stderr(&denied).contains("result_unrecorded"));
    let restored = f.undo(id, &["--created-by-agent", "--unrecorded"]);
    assert!(restored.status.success(), "{}", stderr(&restored));
    assert!(std::fs::read(&f.path).unwrap() == before);
}
#[test]
fn gate37_confirmation_rechecks_matches_and_never_uses_stale_items() {
    for at in [0, 1] {
        let f = Fixture::new();
        let before = std::fs::read(&f.path).unwrap();
        let (child, pause) = paused(&f, at);
        let value = secret_file(
            f._outside.path(),
            "next",
            by_label(&f.values, labels::GITHUB_TOKEN).value(),
        );
        let rotated = run_on_terminal(
            &f.home,
            &[
                "rotate",
                "openai/acme-web",
                "--stdin",
                "--passphrase-fd",
                "3",
            ],
            &[(0, &value, true), (3, &f.pass, true)],
        );
        assert!(rotated.status.success(), "{}", stderr(&rotated));
        let out = finish(child, pause.path(), at);
        assert!(!out.status.success());
        assert!(stdout(&out).contains("items_changed"));
        assert!(std::fs::read(&f.path).unwrap() == before);
    }
}

#[test]
fn gate37_leftovers_reported_on_undo_success_and_refusal_without_deleting_foreign_files() {
    let f = Fixture::new();
    let id = backup(&f.scrub(false));
    let new = f
        .path
        .with_file_name(".events.jsonl.envcloak-new-0000000000000022.tmp");
    let swap = f
        .path
        .with_file_name(".events.jsonl.envcloak-swap-0000000000000023.tmp");
    for p in [&new, &swap] {
        std::fs::write(p, b"foreign fixture").unwrap();
    }
    let restored = f.undo(&id, &[]);
    assert!(restored.status.success(), "{}", stderr(&restored));
    let report: Value = serde_json::from_slice(&restored.stdout).unwrap();
    assert_eq!(
        report["complete"], true,
        "reported leftovers are not restore failures"
    );
    assert_eq!(report["leftovers"].as_array().unwrap().len(), 2);
    std::fs::write(&f.path, b"later edit").unwrap();
    let denied = f.undo(&id, &[]);
    assert!(!denied.status.success());
    let report: Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(report["leftovers"].as_array().unwrap().len(), 2);
    for p in [&new, &swap] {
        assert!(std::fs::read(p).unwrap() == b"foreign fixture");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn gate37_traced_scrub_refuses_before_reading_plaintext() {
    let f = Fixture::new();
    let file = std::fs::File::open(&f.path).unwrap();
    let reset = || {
        file.set_times(std::fs::FileTimes::new().set_accessed(SystemTime::UNIX_EPOCH))
            .unwrap()
    };
    reset();
    // A missing confirmation still reaches the read and proves the atime observer.
    let out = run(
        &f.home,
        &["scrub", "--path", f.path.to_str().unwrap(), "--json"],
        &[],
    );
    assert!(!out.status.success());
    assert!(std::fs::metadata(&f.path).unwrap().accessed().unwrap() > SystemTime::UNIX_EPOCH);
    reset();
    let mut cmd = std::process::Command::new(cli());
    f.home
        .apply(&mut cmd)
        .args([
            "scrub",
            "--path",
            f.path.to_str().unwrap(),
            "--yes",
            "--json",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = envcloak_sys::testing::spawn_traced(&mut cmd)
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).starts_with("envcloak: traced:"));
    assert!(out.stdout.is_empty());
    assert_eq!(
        std::fs::metadata(&f.path).unwrap().accessed().unwrap(),
        SystemTime::UNIX_EPOCH
    );
}
#[test]
fn gate37_python_encoded_jsonl_is_scrubbed_and_remains_valid() {
    use std::io::Write;
    let f = Fixture::new();
    let mut emitter = std::process::Command::new("/usr/bin/python3");
    f.home
        .apply(&mut emitter)
        .args([
            "-I",
            "-B",
            "-c",
            r#"
import base64,json,sys
v=sys.stdin.read()
print(json.dumps({'raw':v,'base64':base64.b64encode(v.encode()).decode()}))
print('{"escaped":"'+''.join('\\u%04x'%ord(c) for c in v)+'"}')
"#,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = emitter.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(by_label(&f.values, labels::OPENAI_API_KEY).value())
        .unwrap();
    let emitted = child.wait_with_output().unwrap();
    assert!(emitted.status.success());
    assert!(emitted.stderr.is_empty());
    std::fs::write(&f.path, &emitted.stdout).unwrap();
    age(&f.path);
    let out = f.scrub(false);
    assert!(out.status.success(), "{} {}", stderr(&out), stdout(&out));
    let bytes = std::fs::read(&f.path).unwrap();
    envcloak_testkit::assert_no_canary(&bytes, &f.values);
    let mut parser = std::process::Command::new("/usr/bin/python3");
    f.home.apply(&mut parser).args(["-I","-B","-c","import json,sys\nrows=[json.loads(s) for s in sys.stdin]\nassert len(rows)==2\nassert all('[envcloak:redacted:' in v for row in rows for v in row.values())\n"])
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut parser = parser.spawn().unwrap();
    parser.stdin.take().unwrap().write_all(&bytes).unwrap();
    let parsed = parser.wait_with_output().unwrap();
    assert!(parsed.status.success(), "Python rejected scrubbed JSONL");
    assert!(parsed.stdout.is_empty() && parsed.stderr.is_empty());
}
