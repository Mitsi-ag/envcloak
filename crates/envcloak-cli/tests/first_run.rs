//! M2-16 gates 10, 15 and 16 through the real CLI and daemon.
#![allow(clippy::unwrap_used)]
mod common;
use common::*;
use envcloak_core::crypto::{ItemClass, KdfParams};
use envcloak_core::vault::{FieldName, ItemDetails, NewItem, Slug, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes, create_vault_with_kit};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};
use serde_json::{Value, json};
use std::path::Path;
use std::time::{Duration, SystemTime};

struct Fixture {
    home: TestHome,
    _daemon: Daemon,
    values: Vec<Canary>,
}
impl Fixture {
    fn new(confirmed: bool) -> Self {
        let home = TestHome::new();
        let values = canaries(fresh_seed());
        let pass = by_label(&values, labels::VAULT_PASSPHRASE);
        let mut vault = create_vault_with_kit(
            &VaultPaths::under(data_dir(&home)),
            &SecretBytes::copy_from(pass.value()),
            &RecoveryKit::generate(),
            KdfParams::minimum(),
        )
        .unwrap();
        vault
            .transact(|t| {
                t.set_recovery_confirmed(confirmed);
                for (slug, label) in [
                    ("openai/existing", labels::OPENAI_API_KEY),
                    ("short/existing", labels::SHORT_TOKEN),
                ] {
                    let id = t.create_item(NewItem {
                        class: ItemClass::Secret,
                        slug: Slug::new(slug).unwrap(),
                        details: ItemDetails::default(),
                    })?;
                    t.add_field(
                        id,
                        FieldName::new("value").unwrap(),
                        SecretBytes::copy_from(by_label(&values, label).value()),
                    )?;
                }
                Ok(())
            })
            .unwrap();
        drop(vault);
        let daemon = start_daemon(&home);
        let outside = outside_dir();
        let pass_file = secret_file(outside.path(), "pass", pass.value());
        assert!(
            run_on_terminal(
                &home,
                &["unlock", "--passphrase-fd", "3"],
                &[(3, &pass_file, true)]
            )
            .status
            .success()
        );
        Self {
            home,
            _daemon: daemon,
            values,
        }
    }
    fn value(&self) -> &str {
        by_label(&self.values, labels::OPENAI_API_KEY).as_str()
    }
    fn scan(&self, flags: &[&str]) -> std::process::Output {
        let mut args = vec!["import", "--machine", "--json"];
        args.extend_from_slice(flags);
        let mut cmd = cli_command(&self.home, &args, &[]);
        cmd.env("CLAUDECODE", "1");
        cmd.env("CLAUDE_CODE_TMPDIR", self.home.home().join("host-tmp"));
        finish_within(cmd, Duration::from_secs(60))
    }
    fn clean(&self, out: &std::process::Output) {
        let control = envcloak_testkit::find(self.value().as_bytes(), &self.values);
        assert!(
            !control.is_empty(),
            "the output sweep's positive control must report raw hits"
        );
        assert_no_canary(&out.stdout, &self.values);
        assert_no_canary(&out.stderr, &self.values);
    }
}
fn age(path: &Path) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(180))
        .unwrap();
}

#[test]
fn gate10_machine_dedupe_dry_run_and_clean_report() {
    let f = Fixture::new(true);
    let home = f.home.home();
    std::fs::create_dir(home.join("app")).unwrap();
    std::fs::write(
        home.join("app/.env"),
        format!("OPENAI_API_KEY={}\n", f.value()),
    )
    .unwrap();
    let profile = format!("export OPENAI_API_KEY={}\n", f.value());
    std::fs::write(home.join(".zshrc"), &profile).unwrap();
    std::fs::write(home.join(".claude.json"),serde_json::to_vec(&json!({"mcpServers":{"fixture":{"command":"fixture","env":{"OPENAI_API_KEY":f.value()}}}})).unwrap()).unwrap();
    assert!(profile.contains(f.value()), "positive exposure control");
    let dry = f.scan(&[]);
    f.clean(&dry);
    assert!(dry.status.success());
    let r: Value = serde_json::from_slice(&dry.stdout).unwrap();
    assert_eq!(r["schema"], "first_run.v1");
    assert_eq!(r["committed"], false);
    assert_eq!(r["items"].as_array().unwrap().len(), 1);
    assert_eq!(r["duplicates_merged"], 2);
    assert!(!home.join("app/envcloak.toml").exists());
    let done = f.scan(&["--yes"]);
    f.clean(&done);
    assert!(done.status.success());
    let r: Value = serde_json::from_slice(&done.stdout).unwrap();
    assert_eq!(r["committed"], true);
    assert_eq!(r["items"][0]["slug"], "openai/existing");
    assert_eq!(r["items"][0]["owning_account"], "unknown");
    assert!(
        r["migrate_mcp"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["slug"] == "openai/existing")
    );
    assert!(std::fs::read(home.join(".zshrc")).unwrap() == profile.as_bytes());
    assert!(home.join("app/envcloak.toml").is_file());
}

#[test]
fn gate16_profile_requires_kit_and_old_complete_assignment() {
    for confirmed in [false, true] {
        let f = Fixture::new(confirmed);
        let path = f.home.home().join(".zshrc");
        let original = format!("export OPENAI_API_KEY={}\nPORT=8080\n", f.value());
        std::fs::write(&path, &original).unwrap();
        if !confirmed {
            age(&path);
        }
        let denied = f.scan(&["--yes", "--delete-plaintext"]);
        f.clean(&denied);
        assert!(
            !denied.status.success(),
            "kit or recent modification must refuse cleanup"
        );
        assert!(std::fs::read(&path).unwrap() == original.as_bytes());
        let report: Value = serde_json::from_slice(&denied.stdout).unwrap();
        assert!(
            report["sources"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|s| s["kept"].as_array().unwrap())
                .any(|kept| kept["name"] == "OPENAI_API_KEY"),
            "a refused cleanup must name the retained binding"
        );
        if confirmed {
            age(&path);
            let done = f.scan(&["--yes", "--delete-plaintext"]);
            f.clean(&done);
            let diagnostic: Value = serde_json::from_slice(&done.stdout).unwrap();
            assert!(done.status.success(), "{}", diagnostic["incomplete"]);
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes
                    .windows(f.value().len())
                    .any(|w| w == f.value().as_bytes())
            );
            assert!(bytes.ends_with(b"PORT=8080\n"));
            let r: Value = serde_json::from_slice(&done.stdout).unwrap();
            assert!(!r["backups"].as_array().unwrap().is_empty());
        }
    }
}

#[test]
fn agent_scan_leaves_guessable_and_ambiguous_assignments() {
    let f = Fixture::new(true);
    let original = format!(
        "export SHORT_TOKEN={}\nexport MULTI_SECRET='first\nsecond'\nexport DYNAMIC_SECRET=$OTHER\n",
        by_label(&f.values, labels::SHORT_TOKEN).as_str()
    );
    let path = f.home.home().join(".zshrc");
    std::fs::write(&path, &original).unwrap();
    age(&path);
    let out = f.scan(&["--yes", "--delete-plaintext"]);
    f.clean(&out);
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        !r["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["slug"] == "short/existing")
    );
    let kept = r["sources"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|x| x["kept"].as_array().unwrap());
    assert!(kept.into_iter().any(|x| x["name"] == "MULTI_SECRET"));
    assert!(std::fs::read(&path).unwrap() == original.as_bytes());
}

#[test]
fn bounded_ten_thousand_file_tree_and_machine_skips() {
    let f = Fixture::new(true);
    let home = f.home.home();
    for d in 0..100 {
        let dir = home.join(format!("tree{d}"));
        std::fs::create_dir(&dir).unwrap();
        for n in 0..100 {
            std::fs::write(dir.join(format!("plain{n}")), b"nothing to import").unwrap();
        }
    }
    std::fs::create_dir(home.join("app")).unwrap();
    std::fs::write(
        home.join("app/.env"),
        format!("OPENAI_API_KEY={}\n", f.value()),
    )
    .unwrap();
    for dir in [
        "node_modules/pkg",
        ".cache",
        ".Trash",
        "Library/Caches",
        "Library/CloudStorage/fixture",
        "Library/Mobile Documents/fixture",
    ] {
        let path = home.join(dir);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(
            path.join(".env"),
            format!(
                "SECRET_TOKEN={}\n",
                by_label(&f.values, labels::GITHUB_TOKEN).as_str()
            ),
        )
        .unwrap();
    }
    let sourced = home.join("Library/CloudStorage/fixture/secrets.sh");
    std::fs::write(
        &sourced,
        format!(
            "export GITHUB_TOKEN={}\n",
            by_label(&f.values, labels::GITHUB_TOKEN).as_str()
        ),
    )
    .unwrap();
    std::fs::write(
        home.join(".zshrc"),
        b"source \"$HOME/Library/CloudStorage/fixture/secrets.sh\"\n",
    )
    .unwrap();
    let start = std::time::Instant::now();
    let out = f.scan(&["--dry-run"]);
    f.clean(&out);
    assert!(start.elapsed() < Duration::from_secs(60));
    assert!(out.status.success());
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["items"].as_array().unwrap().len(), 1);
    assert_eq!(r["items"][0]["slug"], "openai/existing");
    assert!(!home.join("app/envcloak.toml").exists());
    let named = home.join("Library/CloudStorage/fixture");
    let out = f.scan(&["--scan", named.to_str().unwrap()]);
    f.clean(&out);
    assert!(out.status.success());
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        r["items"].as_array().unwrap().len(),
        2,
        "explicitly named cloud root must be scanned"
    );
}

#[test]
fn failures_and_hostile_metadata_never_report_success_or_values() {
    let f = Fixture::new(true);
    let home = f.home.home();
    let hostile = home.join(f.value());
    std::fs::create_dir(&hostile).unwrap();
    std::fs::write(
        hostile.join(".env"),
        format!("OPENAI_API_KEY={}\n", f.value()),
    )
    .unwrap();
    std::os::unix::fs::symlink("missing", home.join(".zshrc")).unwrap();
    let out = f.scan(&["--dry-run"]);
    f.clean(&out);
    assert!(!out.status.success());
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!r["incomplete"].as_array().unwrap().is_empty());
    assert!(!String::from_utf8(out.stdout).unwrap().contains("\"line\""));
}

fn paused(f: &Fixture, at: &str, kill: bool, action: impl FnOnce()) -> std::process::ExitStatus {
    use std::process::Stdio;
    struct Owned {
        child: std::process::Child,
        reaped: bool,
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.reaped {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
    let pause = tempfile::tempdir_in("/tmp").unwrap();
    // The wrapper execs the CLI. This unreaped child handle owns the exact
    // process killed below; the barrier file's pid is never read or signalled.
    let mut command = cli_command(
        &f.home,
        &[
            "import",
            "--machine",
            "--yes",
            "--delete-plaintext",
            "--json",
        ],
        &[],
    );
    command
        .env(envcloak_scan::testing::PAUSE_DIR, pause.path())
        .env("CLAUDE_CODE_TMPDIR", f.home.home().join("host-tmp"))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut owner = Owned {
        child: command.spawn().unwrap(),
        reaped: false,
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let mut n = 0;
    let mut action = Some(action);
    let mut reached = false;
    loop {
        if let Some(status) = owner.child.try_wait().unwrap() {
            owner.reaped = true;
            assert!(reached, "required boundary was not reached");
            return status;
        }
        if std::time::Instant::now() > deadline {
            let _ = owner.child.kill();
            owner.reaped = owner.child.wait().is_ok();
            panic!("first-run boundary timed out");
        }
        let prefix = format!("{n:03}.");
        let point = std::fs::read_dir(pause.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|p| p.file_name().to_string_lossy().into_owned())
            .find(|p| p.starts_with(&prefix) && !p.ends_with(".go"));
        if let Some(point) = point {
            if point[prefix.len()..] == *at {
                reached = true;
                action.take().unwrap()();
                if kill {
                    owner.child.kill().unwrap();
                    let status = owner.child.wait().unwrap();
                    owner.reaped = true;
                    return status;
                }
            }
            std::fs::write(pause.path().join(format!("{n:03}.go")), b"").unwrap();
            n += 1;
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[test]
fn gate16_kill_at_each_profile_and_aws_boundary_preserves_value() {
    for source in ["profile", "aws"] {
        for step in [
            "first_run_planned",
            "first_run_committed",
            "first_run_verified",
            "first_run_backed_up",
            "first_run_reverified",
            "first_run_staged",
            "first_run_swapped",
            "first_run_rewritten",
            "first_run_recorded",
        ] {
            let f = Fixture::new(true);
            let key = by_label(&f.values, labels::GITHUB_TOKEN).as_str();
            let path = if source == "profile" {
                f.home.home().join(".zshrc")
            } else {
                std::fs::create_dir(f.home.home().join(".aws")).unwrap();
                f.home.home().join(".aws/credentials")
            };
            let original = if source == "profile" {
                format!("export GITHUB_TOKEN={key}\nPORT=8080\n")
            } else {
                format!("[default]\naws_secret_access_key = {key}\nregion = ap-southeast-2\n")
            };
            std::fs::write(&path, &original).unwrap();
            age(&path);
            assert!(!paused(&f, step, true, || {}).success());
            let bytes = std::fs::read(&path).unwrap();
            let plaintext = bytes.windows(key.len()).any(|b| b == key.as_bytes());
            let out = run(&f.home, &["ls", "--json"], &[]);
            f.clean(&out);
            assert!(out.status.success());
            let metadata: Value = serde_json::from_slice(&out.stdout).unwrap();
            let committed = metadata["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["slug"].as_str().unwrap().starts_with("github/"));
            assert!(
                plaintext || committed,
                "neither plaintext nor committed item survived"
            );
            if step == "first_run_planned" {
                assert!(plaintext && !committed);
            }
            if matches!(
                step,
                "first_run_swapped" | "first_run_rewritten" | "first_run_recorded"
            ) {
                assert!(
                    !plaintext && committed,
                    "rewrite must actually have occurred"
                );
            }
        }
    }
}

#[test]
fn gate16_lock_after_backup_refuses_stale_verification() {
    let f = Fixture::new(true);
    let path = f.home.home().join(".zshrc");
    let original = format!("export OPENAI_API_KEY={}\n", f.value());
    std::fs::write(&path, &original).unwrap();
    age(&path);
    let status = paused(&f, "first_run_backed_up", false, || {
        assert!(run(&f.home, &["lock"], &[]).status.success());
    });
    assert!(!status.success());
    assert!(std::fs::read(&path).unwrap() == original.as_bytes());
}

#[test]
fn gate16_each_cleanup_condition_is_checked_again() {
    for condition in ["stored", "resolves", "backup", "open_elsewhere"] {
        let f = Fixture::new(true);
        let path = f.home.home().join(".zshrc");
        let original = format!("export OPENAI_API_KEY={}\n", f.value());
        std::fs::write(&path, &original).unwrap();
        age(&path);
        let held = (condition == "open_elsewhere").then(|| std::fs::File::open(&path).unwrap());
        let at = if condition == "backup" {
            "first_run_verified"
        } else {
            "first_run_backed_up"
        };
        let status = paused(&f, at, false, || match condition {
            "stored" => {
                let outside = outside_dir();
                let pass = secret_file(
                    outside.path(),
                    "pass",
                    by_label(&f.values, labels::VAULT_PASSPHRASE).value(),
                );
                let replacement = secret_file(
                    outside.path(),
                    "replacement",
                    by_label(&f.values, labels::STRIPE_SECRET_KEY).value(),
                );
                let out = run_on_terminal(
                    &f.home,
                    &[
                        "rotate",
                        "openai/existing",
                        "--stdin",
                        "--passphrase-fd",
                        "3",
                        "--json",
                    ],
                    &[(0, &replacement, true), (3, &pass, true)],
                );
                f.clean(&out);
                assert!(out.status.success());
            }
            "resolves" => {
                use std::io::Write;
                let manifest = f.home.home().join(".envcloak-import-zshrc/envcloak.toml");
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(manifest)
                    .unwrap()
                    .write_all(b"MISSING = \"missing/fixture\"\n")
                    .unwrap();
            }
            "backup" => {
                let backups = data_dir(&f.home).join("backups");
                if backups.exists() {
                    std::fs::remove_dir(&backups).unwrap();
                }
                std::fs::write(backups, b"blocked").unwrap();
            }
            _ => (),
        });
        assert!(
            !status.success(),
            "cleanup condition {condition} was bypassed"
        );
        assert!(
            std::fs::read(&path).unwrap() == original.as_bytes(),
            "cleanup condition {condition} lost plaintext"
        );
        drop(held);
    }
}

#[test]
fn mcp_header_literals_are_imported_and_handed_off_by_name() {
    let f = Fixture::new(true);
    let path = f.home.home().join(".claude.json");
    let original = serde_json::to_vec(&json!({"mcpServers":{"fixture":{"type":"http","url":"https://example.invalid/mcp","headers":{"x-api-key":f.value()}}}})).unwrap();
    std::fs::write(&path, &original).unwrap();
    let out = f.scan(&["--yes"]);
    f.clean(&out);
    assert!(out.status.success());
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["items"][0]["slug"], "openai/existing");
    assert_eq!(r["migrate_mcp"][0]["name"], "MCP_HEADER_X_API_KEY");
    assert!(std::fs::read(path).unwrap() == original);
}

#[test]
fn gate15_hard_links_are_importable_but_never_rewritten() {
    let f = Fixture::new(true);
    let path = f.home.home().join(".zshrc");
    let original = format!("export OPENAI_API_KEY={}\n", f.value());
    std::fs::write(&path, &original).unwrap();
    age(&path);
    let alias = f.home.home().join("hardlink");
    std::fs::hard_link(&path, &alias).unwrap();
    let out = f.scan(&["--yes", "--delete-plaintext"]);
    f.clean(&out);
    assert!(!out.status.success());
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["items"][0]["slug"], "openai/existing");
    assert!(std::fs::read(&path).unwrap() == original.as_bytes());
    assert!(std::fs::read(&alias).unwrap() == original.as_bytes());
}

#[test]
fn gate16_profile_undo_is_byte_exact_and_checks_the_result() {
    let f = Fixture::new(true);
    let path = f.home.home().join(".zshrc");
    let original = format!(
        "# retained\nexport OPENAI_API_KEY={}\nPORT=8080\n",
        f.value()
    );
    std::fs::write(&path, &original).unwrap();
    age(&path);
    let out = run_on_terminal(
        &f.home,
        &[
            "import",
            "--machine",
            "--yes",
            "--delete-plaintext",
            "--json",
        ],
        &[],
    );
    f.clean(&out);
    assert!(out.status.success());
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    let id = r["backups"][0].as_str().unwrap();
    let after = std::fs::read(&path).unwrap();
    let mut edited = after.clone();
    edited.extend_from_slice(b"# user edit\n");
    std::fs::write(&path, &edited).unwrap();
    let outside = outside_dir();
    let pass = secret_file(
        outside.path(),
        "pass",
        by_label(&f.values, labels::VAULT_PASSPHRASE).value(),
    );
    let args = ["init", "--undo", id, "--passphrase-fd", "3", "--json"];
    let refused = run_on_terminal(&f.home, &args, &[(3, &pass, true)]);
    f.clean(&refused);
    assert!(!refused.status.success());
    assert!(std::fs::read(&path).unwrap() == edited);
    std::fs::write(&path, &after).unwrap();
    let restored = run_on_terminal(&f.home, &args, &[(3, &pass, true)]);
    f.clean(&restored);
    assert!(restored.status.success());
    assert!(std::fs::read(&path).unwrap() == original.as_bytes());
}

#[test]
fn doctor_exposure_is_reported_without_copying_values() {
    let f = Fixture::new(true);
    let home = f.home.home();
    let transcript = home.join(".claude/projects/fixture/session.jsonl");
    std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    let encoded = serde_json::to_vec(&json!({"text":f.value()})).unwrap();
    let mut lines = encoded;
    lines.push(b'\n');
    std::fs::write(transcript, &lines).unwrap();
    std::fs::write(
        home.join(".zshrc"),
        format!("export OPENAI_API_KEY={}\n", f.value()),
    )
    .unwrap();
    let mut command = cli_command(&f.home, &["doctor", "--json"], &[]);
    command.env("CLAUDE_CODE_TMPDIR", home.join("host-tmp"));
    let doctor = finish_within(command, Duration::from_secs(60));
    f.clean(&doctor);
    assert!(doctor.status.success());
    let out = f.scan(&["--dry-run"]);
    f.clean(&out);
    assert!(out.status.success());
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        r["leaked"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["slug"] == "openai/existing")
    );
}

#[test]
fn gate15_sourced_names_never_become_plaintext_ignore_entries() {
    let f = Fixture::new(true);
    let directory = f.home.home().join(".claude");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(f.value());
    let original = format!("export OPENAI_API_KEY={}\n", f.value());
    std::fs::write(&path, &original).unwrap();
    age(&path);
    std::fs::write(
        f.home.home().join(".zshrc"),
        format!("source \"$HOME/.claude/{}\"\n", f.value()),
    )
    .unwrap();
    let out = f.scan(&["--yes", "--delete-plaintext"]);
    f.clean(&out);
    assert!(
        !out.status.success(),
        "unsafe source names must be refused before cleanup"
    );
    assert!(std::fs::read(&path).unwrap() == original.as_bytes());
    if let Ok(ignore) = std::fs::read(directory.join(".gitignore")) {
        assert_no_canary(&ignore, &f.values);
    }
}

#[test]
fn retained_config_temporaries_are_reported_as_incomplete() {
    let f = Fixture::new(true);
    let directory = f.home.home().join(".claude");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("settings.json"), b"{}").unwrap();
    let leftover = directory.join(format!(
        ".settings.json.envcloak-new-{:016x}.tmp",
        fresh_seed()
    ));
    std::fs::write(&leftover, f.value()).unwrap();
    let out = f.scan(&["--dry-run"]);
    f.clean(&out);
    assert!(
        !out.status.success(),
        "retained plaintext must not be reported as a complete scan"
    );
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        r["incomplete"]
            .as_array()
            .unwrap()
            .contains(&json!("leftover"))
    );
    assert!(std::fs::read(&leftover).unwrap() == f.value().as_bytes());
}

#[test]
fn gate16_a_rewrite_must_fit_the_undo_read_limit() {
    let f = Fixture::new(true);
    let path = f.home.home().join(".zshrc");
    let short = by_label(&f.values, labels::SHORT_TOKEN).as_str();
    let mut original = format!("SHORT_TOKEN={short}\n#").into_bytes();
    original.resize(envcloak_scan::MAX_DOTENV, b'.');
    std::fs::write(&path, &original).unwrap();
    age(&path);
    // A person may import this existing short item. Its replacement comment
    // is longer than the assignment, so the one-MiB source would grow.
    let out = run_on_terminal(
        &f.home,
        &[
            "import",
            "--machine",
            "--yes",
            "--delete-plaintext",
            "--json",
        ],
        &[],
    );
    f.clean(&out);
    assert!(
        !out.status.success(),
        "cleanup must retain a file whose result undo cannot read"
    );
    assert!(std::fs::read(&path).unwrap() == original);
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        r["sources"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|s| s["kept"].as_array().unwrap())
            .any(|e| e["name"] == "SHORT_TOKEN" && e["reason"] == "too_large")
    );
}
