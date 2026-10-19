//! M2-23 gate 10 and export isolation. Documented format, not tool output.
#![allow(clippy::unwrap_used)]
mod common;
use common::*;
use envcloak_core::crypto::KdfParams;
use envcloak_core::vault::VaultPaths;
use envcloak_core::{RecoveryKit, SecretBytes, create_vault_with_kit};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};
use serde_json::{Value, json};
use std::path::Path;
use std::process::Output;
use std::time::Duration;

struct Fixture {
    home: TestHome,
    daemon: Daemon,
    values: Vec<Canary>,
}
impl Fixture {
    fn new() -> Self {
        let home = TestHome::new();
        let values = canaries(fresh_seed());
        let pass = by_label(&values, labels::VAULT_PASSPHRASE);
        drop(
            create_vault_with_kit(
                &VaultPaths::under(data_dir(&home)),
                &SecretBytes::copy_from(pass.value()),
                &RecoveryKit::generate(),
                KdfParams::minimum(),
            )
            .unwrap(),
        );
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
            daemon,
            values,
        }
    }
    fn key(&self) -> &str {
        by_label(&self.values, labels::OPENAI_API_KEY).as_str()
    }
    fn command(&self, args: &[&str], person: bool) -> Output {
        let mut cmd = if person {
            on_terminal_command(&self.home, args, &[])
        } else {
            cli_command(&self.home, args, &[])
        };
        if !person {
            cmd.env("CLAUDECODE", "1");
        }
        let out = finish_within(cmd, Duration::from_secs(90));
        assert!(!envcloak_testkit::find(self.key().as_bytes(), &self.values).is_empty());
        assert_no_canary(&out.stdout, &self.values);
        assert_no_canary(&out.stderr, &self.values);
        out
    }
    fn export(&self, kind: &str, path: &Path, yes: bool, person: bool) -> Output {
        self.command(
            &[
                "import",
                "--from",
                kind,
                path.to_str().unwrap(),
                if yes { "--yes" } else { "--dry-run" },
                "--json",
            ],
            person,
        )
    }
}
fn wire(kind: &str, value: &str) -> Vec<u8> {
    match kind {
        "doppler-json"=>serde_json::to_vec(&json!({"SERVICE_TOKEN":value})).unwrap(),
        "infisical-json"=>serde_json::to_vec(&json!([{"key":"SERVICE_TOKEN","value":value,"workspace":"","type":"shared","_id":"","secretPath":"/","tags":null,"comment":"","Etag":"","skipMultilineEncoding":false}])).unwrap(),
        "bitwarden-json"=>serde_json::to_vec(&json!({"encrypted":false,"items":[{"type":1,"name":"fixture","login":{"password":value}}]})).unwrap(),
        "1password-csv"=>format!("Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\r\nfixture,,,\"{}\",,false,false,,\r\n",value.replace('"',"\"\"")).into_bytes(),
        "dotenv"=>format!("SERVICE_TOKEN='{value}'\n").into_bytes(),
        "aws-credentials"=>format!("[default]\naws_secret_access_key={value}\n").into_bytes(),
        _=>panic!("unknown fixture kind"),
    }
}
#[test]
fn gate10_exports_merge_with_dotenv_in_both_orders_and_retain_the_source() {
    for first in [false, true] {
        let f = Fixture::new();
        let home = f.home.home();
        let project = home.join("app");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join(".env"), format!("SERVICE_TOKEN={}\n", f.key())).unwrap();
        if !first {
            assert!(
                f.command(
                    &[
                        "import",
                        "--scan",
                        project.to_str().unwrap(),
                        "--yes",
                        "--json"
                    ],
                    false
                )
                .status
                .success()
            );
        }
        for kind in [
            "doppler-json",
            "infisical-json",
            "bitwarden-json",
            "1password-csv",
            "aws-credentials",
            "dotenv",
        ] {
            let path = home.join("export");
            let bytes = wire(kind, f.key());
            std::fs::write(&path, &bytes).unwrap();
            let dry = f.export(kind, &path, false, false);
            assert!(dry.status.success());
            let report: Value = serde_json::from_slice(&dry.stdout).unwrap();
            assert_eq!(report["committed"], false);
            assert_eq!(report["imported_entries"], 0);
            let out = f.export(kind, &path, true, false);
            assert!(out.status.success());
            let report: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(report["schema"], "export_import.v1");
            assert_eq!(report["source"], "export");
            assert_eq!(report["imported_entries"], 1);
            assert_eq!(report["items"].as_array().unwrap().len(), 1);
            assert_eq!(report["source_retained"], true);
            assert!(std::fs::read(&path).unwrap() == bytes);
            assert!(!home.join("envcloak.toml").exists());
            assert!(!home.join(".gitignore").exists());
        }
        if first {
            assert!(
                f.command(
                    &[
                        "import",
                        "--scan",
                        project.to_str().unwrap(),
                        "--yes",
                        "--json"
                    ],
                    false
                )
                .status
                .success()
            );
        }
        let out = f.command(&["ls", "--json"], false);
        let items: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(items["items"].as_array().unwrap().len(), 1);
        assert_no_canary(&f.daemon.log_bytes(), &f.values);
    }
}
#[test]
fn guessable_rule_uses_the_same_daemon_policy_for_exports_and_dotenv() {
    let f = Fixture::new();
    let path = f.home.home().join("export");
    let short = by_label(&f.values, labels::SHORT_TOKEN).as_str();
    for kind in [
        "doppler-json",
        "infisical-json",
        "bitwarden-json",
        "1password-csv",
        "aws-credentials",
        "dotenv",
    ] {
        std::fs::write(&path, wire(kind, short)).unwrap();
        let agent = f.export(kind, &path, true, false);
        assert!(!agent.status.success());
        let report: Value = serde_json::from_slice(&agent.stdout).unwrap();
        assert_eq!(report["imported_entries"], 0);
        assert_eq!(report["skipped"]["guessable"], 1);
        let person = f.export(kind, &path, true, true);
        assert!(person.status.success());
        let report: Value = serde_json::from_slice(&person.stdout).unwrap();
        assert_eq!(report["imported_entries"], 1);
    }
}
#[test]
fn malformed_tail_and_unknown_shapes_never_commit_or_echo_a_row() {
    let f = Fixture::new();
    let path = f.home.home().join("export");
    for kind in [
        "doppler-json",
        "infisical-json",
        "bitwarden-json",
        "1password-csv",
        "aws-credentials",
        "dotenv",
    ] {
        let mut bytes = wire(kind, f.key());
        bytes.extend_from_slice(b"\ninvalid tail");
        std::fs::write(&path, &bytes).unwrap();
        let out = f.export(kind, &path, true, false);
        assert!(!out.status.success());
        assert!(std::fs::read(&path).unwrap() == bytes);
    }
    let out = f.command(&["ls", "--json"], false);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["items"].as_array().unwrap().is_empty());
}
#[test]
fn exports_refuse_symlinks_fifos_and_cleanup_options() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let home = f.home.home();
    let path = home.join("export");
    let target = home.join("original");
    let bytes = wire("doppler-json", f.key());
    std::fs::write(&target, &bytes).unwrap();
    symlink(&target, &path).unwrap();
    assert!(
        !f.export("doppler-json", &path, true, false)
            .status
            .success()
    );
    let fifo = home.join("fifo");
    let status = std::process::Command::new("mkfifo")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        !f.export("doppler-json", &fifo, true, false)
            .status
            .success()
    );
    for extra in ["--delete-plaintext", "--machine", "--scan"] {
        let out = f.command(
            &[
                "import",
                "--from",
                "doppler-json",
                target.to_str().unwrap(),
                "--yes",
                extra,
            ],
            false,
        );
        assert_eq!(out.status.code(), Some(2));
    }
    assert!(std::fs::read(target).unwrap() == bytes);
}

#[test]
fn dry_run_writes_nothing_and_vault_changes_invalidate_the_reviewed_plan() {
    use std::process::Stdio;
    let f = Fixture::new();
    let home = f.home.home();
    let path = home.join("export");
    std::fs::write(&path, wire("doppler-json", f.key())).unwrap();
    assert!(
        f.export("doppler-json", &path, false, false)
            .status
            .success()
    );
    let out = f.command(&["ls", "--json"], false);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["items"].as_array().unwrap().is_empty());
    let pause = tempfile::tempdir_in("/tmp").unwrap();
    let out_path = pause.path().join("out");
    let err_path = pause.path().join("err");
    let mut command = cli_command(
        &f.home,
        &[
            "import",
            "--from",
            "doppler-json",
            path.to_str().unwrap(),
            "--yes",
            "--json",
        ],
        &[],
    );
    command
        .env("CLAUDECODE", "1")
        .env(envcloak_scan::testing::PAUSE_DIR, pause.path())
        .stdout(Stdio::from(std::fs::File::create(&out_path).unwrap()))
        .stderr(Stdio::from(std::fs::File::create(&err_path).unwrap()));
    struct Owned(Option<std::process::Child>);
    impl Drop for Owned {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let mut owned = Owned(Some(command.spawn().unwrap()));
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    while !pause.path().join("000.export_planned").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "plan barrier timed out"
        );
        if owned.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            owned.0 = None;
            panic!("exited before barrier");
        }
        std::thread::yield_now();
    }
    // Another successful import changes the dedupe plan after review. The
    // first operation must not silently re-approve that new plan.
    assert!(
        f.export("doppler-json", &path, true, false)
            .status
            .success()
    );
    std::fs::write(pause.path().join("000.go"), b"").unwrap();
    let status = loop {
        if let Some(status) = owned.0.as_mut().unwrap().try_wait().unwrap() {
            owned.0 = None;
            break status;
        }
        assert!(std::time::Instant::now() < deadline, "commit timed out");
        std::thread::yield_now();
    };
    assert!(!status.success());
    let stdout = std::fs::read(out_path).unwrap();
    let stderr = std::fs::read(err_path).unwrap();
    assert_no_canary(&stdout, &f.values);
    assert_no_canary(&stderr, &f.values);
    assert!(String::from_utf8_lossy(&stderr).contains("plan_changed"));
    assert!(!String::from_utf8_lossy(&stdout).contains("\"committed\":true"));
}
