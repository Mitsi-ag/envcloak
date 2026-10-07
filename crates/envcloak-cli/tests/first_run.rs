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
fn review_cleanup_preserves_ignore_files_and_refuses_before_metadata() {
    for source in [".zshrc", ".aws/credentials"] {
        for condition in ["recent", "hard_link", "open", "allowed"] {
            let f = Fixture::new(true);
            let home = f.home.home();
            std::fs::create_dir(home.join(".aws")).unwrap();
            let ignore = b"# global exclusions\n*.scratch\n!/.zshrc\n";
            std::fs::write(home.join(".gitignore"), ignore).unwrap();
            let path = home.join(source);
            let original = if source == ".zshrc" {
                format!("export OPENAI_API_KEY={}\n", f.value())
            } else {
                format!("[default]\naws_secret_access_key = {}\n", f.value())
            };
            std::fs::write(&path, &original).unwrap();
            if condition != "recent" {
                age(&path);
            }
            if condition == "hard_link" {
                std::fs::hard_link(&path, home.join("alias")).unwrap();
            }
            let held = (condition == "open").then(|| std::fs::File::open(&path).unwrap());
            let out = f.scan(&["--yes", "--delete-plaintext"]);
            f.clean(&out);
            assert_eq!(
                out.status.success(),
                condition == "allowed",
                "{source}: {condition}"
            );
            assert_eq!(std::fs::read(home.join(".gitignore")).unwrap(), ignore);
            assert!(!home.join(".aws/.gitignore").exists());
            if condition != "allowed" {
                assert!(std::fs::read(&path).unwrap() == original.as_bytes());
                for parent in [home.clone(), home.join(".aws")] {
                    assert!(
                        !std::fs::read_dir(parent).unwrap().any(|e| e
                            .unwrap()
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".envcloak-import-")),
                        "refusal created metadata: {condition}"
                    );
                }
            }
            drop(held);
        }
    }
}

#[test]
fn review_repeated_cleanup_names_the_manual_manifest_step() {
    let f = Fixture::new(true);
    let path = f.home.home().join(".zshrc");
    std::fs::write(&path, format!("export OPENAI_API_KEY={}\n", f.value())).unwrap();
    age(&path);
    assert!(f.scan(&["--yes", "--delete-plaintext"]).status.success());
    let prior = std::fs::read(&path).unwrap();
    let mut next = prior;
    next.extend_from_slice(
        format!(
            "export GITHUB_TOKEN={}\n",
            by_label(&f.values, labels::GITHUB_TOKEN).as_str()
        )
        .as_bytes(),
    );
    std::fs::write(&path, &next).unwrap();
    age(&path);
    let out = f.scan(&["--yes", "--delete-plaintext"]);
    f.clean(&out);
    assert!(!out.status.success());
    assert_eq!(std::fs::read(&path).unwrap(), next);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let source = report["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["display_path"].as_str().unwrap().ends_with("/.zshrc"))
        .unwrap();
    assert!(
        source["manual"]
            .as_str()
            .unwrap()
            .contains("Move the private manifest directory aside")
    );
    let human = run(
        &f.home,
        &["import", "--machine", "--yes", "--delete-plaintext"],
        &[],
    );
    f.clean(&human);
    assert!(!human.status.success());
    assert!(
        String::from_utf8(human.stdout)
            .unwrap()
            .contains("Move the private manifest directory aside")
    );
}

#[test]
fn review_mcp_includes_require_cloud_opt_in() {
    let f = Fixture::new(true);
    let home = f.home.home();
    let cloud = home.join("Dropbox");
    std::fs::create_dir(&cloud).unwrap();
    std::fs::write(
        cloud.join("fixture.env"),
        format!("OPENAI_API_KEY={}\n", f.value()),
    )
    .unwrap();
    std::fs::write(
        home.join(".mcp.json"),
        br#"{"mcpServers":{"fixture":{"command":"fixture","envFile":"Dropbox/fixture.env"}}}"#,
    )
    .unwrap();
    let out = f.scan(&["--dry-run"]);
    f.clean(&out);
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["items"].as_array().unwrap().is_empty());
    assert!(
        report["sources"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|s| s["kept"].as_array().unwrap())
            .any(|k| k["reason"] == "volume_opt_in")
    );
    let out = f.scan(&["--dry-run", "--scan", cloud.to_str().unwrap()]);
    f.clean(&out);
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["items"].as_array().unwrap().len(), 1);
}

#[test]
fn review_cloud_selection_covers_case_aliases_in_every_reader() {
    for name in ["dRoPbOx", "oNeDrIvE", "cLoUdStOrAgE", "mObIlE dOcUmEnTs"] {
        let f = Fixture::new(true);
        let home = f.home.home();
        let cloud = home.join(name);
        std::fs::create_dir(&cloud).unwrap();
        let content = format!("OPENAI_API_KEY={}\n", f.value());
        std::fs::write(cloud.join(".env"), &content).unwrap();
        std::fs::write(cloud.join("fixture.env"), &content).unwrap();
        let lowercase = name.to_ascii_lowercase();
        let referenced_dir = if home.join(&lowercase).is_dir() {
            &lowercase
        } else {
            name
        };
        std::fs::write(
            home.join(".zshrc"),
            format!("source '{referenced_dir}/fixture.env'\n"),
        )
        .unwrap();
        std::fs::write(home.join(".mcp.json"), serde_json::to_vec(&json!({"mcpServers":{"fixture":{"command":"fixture","envFile":format!("{referenced_dir}/fixture.env")}}})).unwrap()).unwrap();
        let out = f.scan(&["--dry-run"]);
        f.clean(&out);
        assert!(out.status.success());
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(report["items"].as_array().unwrap().is_empty(), "{name}");
        let out = f.scan(&["--scan", cloud.to_str().unwrap(), "--dry-run"]);
        f.clean(&out);
        assert!(out.status.success());
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["items"].as_array().unwrap().len(), 1, "{name}");
        assert!(
            !report["sources"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["kept"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|k| k["reason"] == "volume_opt_in")),
            "{name}"
        );
    }
}

#[test]
fn review_nested_projects_need_no_dotenv_to_discover_mcp() {
    for name in [".mcp.json", ".cursor/mcp.json"] {
        let f = Fixture::new(true);
        let path = f.home.home().join("projects/only-config").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec(&json!({"mcpServers":{"fixture":{"command":"fixture","env":{"OPENAI_API_KEY":f.value()}}}})).unwrap()).unwrap();
        let out = f.scan(&["--dry-run"]);
        f.clean(&out);
        assert!(out.status.success());
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["items"].as_array().unwrap().len(), 1, "{name}");
        assert_eq!(report["migrate_mcp"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn review_catalog_discovery_through_an_explicit_root_alias() {
    let f = Fixture::new(true);
    std::fs::write(
        f.home.home().join(".claude.json"),
        serde_json::to_vec(&json!({"mcpServers":{"fixture":{"command":"fixture","env":{"OPENAI_API_KEY":f.value()}}}})).unwrap(),
    ).unwrap();
    let outside = outside_dir();
    let alias = outside.path().join("alias");
    std::os::unix::fs::symlink(f.home.home(), &alias).unwrap();
    for machine in [true, false] {
        let args = if machine {
            vec!["import", "--machine", "--dry-run", "--json"]
        } else {
            vec![
                "import",
                "--scan",
                alias.to_str().unwrap(),
                "--dry-run",
                "--json",
            ]
        };
        let mut cmd = cli_command(&f.home, &args, &[]);
        cmd.env("HOME", &alias);
        let out = finish_within(cmd, Duration::from_secs(60));
        f.clean(&out);
        assert!(out.status.success());
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            report["items"].as_array().unwrap().len(),
            1,
            "machine: {machine}"
        );
        assert_eq!(report["migrate_mcp"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn review_named_scan_keeps_cache_projects() {
    let f = Fixture::new(true);
    for name in ["Dropbox", "OneDrive"] {
        let dir = f.home.home().join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join(".env"), format!("OPENAI_API_KEY={}\n", f.value())).unwrap();
    }
    for (n, name) in ["cache", "Caches", "caches", "Trash"].iter().enumerate() {
        let dir = f.home.home().join(format!("project{n}")).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".env"), format!("OPENAI_API_KEY={}\n", f.value())).unwrap();
    }
    let out = run(
        &f.home,
        &[
            "import",
            "--scan",
            f.home.home().to_str().unwrap(),
            "--dry-run",
            "--json",
        ],
        &[],
    );
    f.clean(&out);
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    for name in ["Dropbox", "OneDrive"] {
        assert!(report["sources"].as_array().unwrap().iter().any(|s| {
            s["display_path"].as_str().unwrap().ends_with(name)
                && s["kept"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|k| k["reason"] == "excluded_directory")
        }));
    }
    assert_eq!(
        report["sources"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s["kind"] == "dotenv")
            .count(),
        4
    );
    let out = f.scan(&["--dry-run"]);
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["items"].as_array().unwrap().is_empty());
}

#[test]
fn review_dotenv_file_limit_is_incomplete() {
    let f = Fixture::new(true);
    let home = f.home.home();
    let early = home.join("a");
    std::fs::create_dir(&early).unwrap();
    for n in 0..10_000 {
        std::fs::write(early.join(format!(".env.p{n:05}")), b"").unwrap();
    }
    std::fs::create_dir(home.join("z")).unwrap();
    std::fs::write(
        home.join("z/.env"),
        format!("OPENAI_API_KEY={}\n", f.value()),
    )
    .unwrap();
    let out = f.scan(&["--dry-run"]);
    f.clean(&out);
    assert!(
        !out.status.success(),
        "the final credential was outside the file budget"
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        report["incomplete"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "limited")
    );
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
    let mut f = Fixture::new(true);
    // A continued physical line decodes to a full registry-pattern value.
    // Its import must succeed while whole-line cleanup remains forbidden.
    let multiline = format!("{}\nsecond", f.value());
    f.values.push(Canary::new("multiline", multiline.clone()));
    let (first, second) = f.value().split_at(32);
    let original = format!(
        "export SHORT_TOKEN={}\nexport MULTI_SECRET=\"{first}\\\n{second}\"\nexport NEWLINE_SECRET='{multiline}'\nexport DYNAMIC_SECRET=$OTHER\n",
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
    for name in ["MULTI_SECRET", "NEWLINE_SECRET"] {
        assert!(
            r["sources"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|s| s["kept"].as_array().unwrap())
                .any(|k| k["name"] == name && k["reason"] == "manual_assignment")
        );
    }
    assert!(
        r["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["slug"] == "openai/existing")
    );
    assert_eq!(r["sources"][0]["imported"], 2);
    assert_eq!(r["compared"], 2);
    assert_eq!(r["skipped_guessable"], 1);
    assert!(std::fs::read(&path).unwrap() == original.as_bytes());

    f._daemon.signal("-TERM");
    assert!(f._daemon.wait_exit(Duration::from_secs(30)).is_some());
    let vault = envcloak_core::vault::LockedVault::open(&VaultPaths::under(data_dir(&f.home)))
        .unwrap()
        .unlock_with_passphrase(&SecretBytes::copy_from(
            by_label(&f.values, labels::VAULT_PASSPHRASE).value(),
        ))
        .map_err(|(_, error)| error)
        .unwrap();
    let (entries, _) = vault.read_audit().unwrap();
    assert_no_canary(format!("{entries:?}").as_bytes(), &f.values);
    let scans = entries
        .iter()
        .filter(|e| e.record.kind == envcloak_core::audit::AuditKind::ScanMatch)
        .collect::<Vec<_>>();
    assert_eq!(scans.len(), 1);
    let decision = &scans[0].record.decision;
    assert_eq!(decision.method.as_deref(), Some("scan.match"));
    assert_eq!(decision.reason.as_deref(), Some("import"));
    assert_eq!(decision.outcome, "checked");
    assert_eq!(decision.count, Some(2));
    for (name, count) in [
        ("compared_guessable", 0),
        ("compared_other", 2),
        ("skipped_guessable", 1),
        ("candidates_mixed", 3),
    ] {
        assert_eq!(
            decision
                .counts
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, n)| *n),
            Some(count),
            "{name}"
        );
    }
}

#[test]
fn gate16_zsh_expansions_are_manual_in_profiles_and_includes() {
    for source in [".zshrc", ".zprofile", ".zshenv", "included/profile"] {
        for rhs in [
            "=python3",
            "prefix:=python3",
            "''=python3",
            "'prefix:'=python3",
            "prefix:''=python3",
        ] {
            let f = Fixture::new(true);
            let path = f.home.home().join(source);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            if source == "included/profile" {
                std::fs::write(f.home.home().join(".zshrc"), b"source included/profile\n").unwrap();
            }
            let original = format!("export SECRET_TOKEN={rhs}\n");
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
            let report: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert!(
                std::fs::read(&path).unwrap() == original.as_bytes(),
                "{source}"
            );
            assert!(!out.status.success());
            assert_eq!(report["compared"], 0);
            assert!(report["items"].as_array().unwrap().is_empty());
            assert!(
                report["sources"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|s| s["kept"].as_array().unwrap())
                    .any(|k| k["name"] == "SECRET_TOKEN" && k["reason"] == "manual_assignment")
            );
        }
    }
}

#[test]
fn aws_colon_credentials_are_imported_before_cleanup() {
    for source in [".aws/credentials", ".aws/config"] {
        let mut f = Fixture::new(true);
        let path = f.home.home().join(source);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let token = format!(
            "{}=padding==",
            by_label(&f.values, labels::GITHUB_TOKEN).as_str()
        );
        f.values.push(Canary::new("aws_padded", token.clone()));
        let original = format!(
            "[default]\naws_secret_access_key: {}\naws_session_token: {token}\nregion = retained\n",
            f.value()
        );
        std::fs::write(&path, &original).unwrap();
        age(&path);
        let out = f.scan(&["--yes", "--delete-plaintext"]);
        f.clean(&out);
        assert!(out.status.success());
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["compared"], 2);
        assert_eq!(report["sources"][0]["imported"], 2);
        assert!(report["sources"][0]["kept"].as_array().unwrap().is_empty());
        let after = std::fs::read(&path).unwrap();
        assert!(after.starts_with(b"[default]\n# envcloak:"));
        assert!(after.ends_with(b"region = retained\n"));
        assert!(
            !after
                .windows(b"aws_session_token".len())
                .any(|w| w == b"aws_session_token")
        );
    }
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
    paused_output(f, at, kill, action).status
}

fn paused_output(f: &Fixture, at: &str, kill: bool, action: impl FnOnce()) -> std::process::Output {
    paused_report(f, at, kill, true, action)
}

fn paused_report(
    f: &Fixture,
    at: &str,
    kill: bool,
    json: bool,
    action: impl FnOnce(),
) -> std::process::Output {
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
    let stdout = pause.path().join("stdout");
    let stderr = pause.path().join("stderr");
    let output = |status| std::process::Output {
        status,
        stdout: std::fs::read(&stdout).unwrap(),
        stderr: std::fs::read(&stderr).unwrap(),
    };
    // The wrapper execs the CLI. This unreaped child handle owns the exact
    // process killed below; the barrier file's pid is never read or signalled.
    let mut args = vec!["import", "--machine", "--yes", "--delete-plaintext"];
    if json {
        args.push("--json");
    }
    let mut command = cli_command(&f.home, &args, &[]);
    command
        .env(envcloak_scan::testing::PAUSE_DIR, pause.path())
        .env("CLAUDE_CODE_TMPDIR", f.home.home().join("host-tmp"))
        .stdout(Stdio::from(std::fs::File::create(&stdout).unwrap()))
        .stderr(Stdio::from(std::fs::File::create(&stderr).unwrap()));
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
            return output(status);
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
                    return output(status);
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
fn review_receipt_failure_preserves_the_completed_rewrite_report() {
    for json in [true, false] {
        let f = Fixture::new(true);
        let path = f.home.home().join(".zshrc");
        std::fs::write(&path, format!("export OPENAI_API_KEY={}\n", f.value())).unwrap();
        age(&path);
        let out = paused_report(&f, "first_run_rewritten", false, json, || {
            assert!(run(&f.home, &["lock"], &[]).status.success());
        });
        f.clean(&out);
        assert!(!out.status.success());
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .starts_with("# envcloak:")
        );
        if !json {
            let text = String::from_utf8(out.stdout).unwrap();
            assert!(text.contains("cleanup: rewritten"));
            assert!(text.contains("backup receipt: unconfirmed"));
            assert!(!text.contains("kept OPENAI_API_KEY"));
            assert!(!text.contains("kept entry: vault_locked"));
            continue;
        }
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        let source = report["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["display_path"].as_str().unwrap().ends_with("/.zshrc"))
            .unwrap();
        assert_eq!(source["cleanup"], "rewritten");
        assert_eq!(source["receipt"], "unconfirmed");
        assert!(source["kept"].as_array().unwrap().is_empty());
        assert!(
            source["replacement"]
                .as_str()
                .unwrap()
                .contains("envcloak run")
        );
        assert_eq!(report["backups"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn review_retained_swap_is_named_separately_from_the_rewritten_source() {
    let f = Fixture::new(true);
    let path = f.home.home().join(".zshrc");
    std::fs::write(&path, format!("export OPENAI_API_KEY={}\n", f.value())).unwrap();
    age(&path);
    let mut kept = None;
    let out = paused_output(&f, "first_run_swapped", false, || {
        let swap = std::fs::read_dir(f.home.home())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("..zshrc.envcloak-swap-")
            })
            .unwrap();
        std::fs::write(&swap, b"another writer's file\n").unwrap();
        kept = Some(swap);
    });
    f.clean(&out);
    assert!(!out.status.success());
    let kept = kept.unwrap();
    assert_eq!(std::fs::read(&kept).unwrap(), b"another writer's file\n");
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let sources = report["sources"].as_array().unwrap();
    let source = sources
        .iter()
        .find(|s| s["display_path"].as_str().unwrap().ends_with("/.zshrc"))
        .unwrap();
    assert_eq!(source["cleanup"], "rewritten");
    assert!(source["kept"].as_array().unwrap().is_empty());
    let leftover = sources
        .iter()
        .find(|s| {
            s["display_path"]
                .as_str()
                .unwrap()
                .ends_with(kept.file_name().unwrap().to_str().unwrap())
        })
        .unwrap();
    assert!(
        leftover["kept"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["reason"] == "aside_changed")
    );
}

#[test]
fn gate16_kill_at_each_profile_and_aws_boundary_preserves_value() {
    for source in ["profile", "include", "aws", "aws_config"] {
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
            let path = match source {
                "profile" => f.home.home().join(".zshrc"),
                "include" => {
                    std::fs::write(f.home.home().join(".zshrc"), b"source .zprofile\n").unwrap();
                    f.home.home().join(".zprofile")
                }
                _ => {
                    std::fs::create_dir(f.home.home().join(".aws")).unwrap();
                    f.home.home().join(if source == "aws" {
                        ".aws/credentials"
                    } else {
                        ".aws/config"
                    })
                }
            };
            let original = if matches!(source, "profile" | "include") {
                format!("export GITHUB_TOKEN={key}\nPORT=8080\n")
            } else {
                format!("[default]\naws_secret_access_key = {key}\nregion = ap-southeast-2\n")
            };
            std::fs::write(&path, &original).unwrap();
            age(&path);
            assert!(!paused(&f, step, true, || {}).success());
            if matches!(step, "first_run_staged" | "first_run_swapped") {
                let scan = f.scan(&["--dry-run"]);
                f.clean(&scan);
                assert!(
                    !scan.status.success(),
                    "interrupted {source} at {step} must be incomplete"
                );
                let report: Value = serde_json::from_slice(&scan.stdout).unwrap();
                assert!(
                    report["incomplete"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|r| r == "leftover")
                );
            }
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
        let mut held = None;
        let at = if condition == "backup" {
            "first_run_verified"
        } else {
            "first_run_backed_up"
        };
        let status = paused(&f, at, false, || match condition {
            "open_elsewhere" => {
                held = Some(std::fs::File::open(&path).unwrap());
            }
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
    for source in [
        ".zshrc",
        "included/profile",
        ".aws/credentials",
        ".aws/config",
    ] {
        let f = Fixture::new(true);
        let path = f.home.home().join(source);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        if source == "included/profile" {
            std::fs::write(f.home.home().join(".zshrc"), b"source included/profile\n").unwrap();
        }
        let original = if source.starts_with(".aws/") {
            format!("[default]\naws_secret_access_key = {}\n", f.value())
        } else {
            format!("export OPENAI_API_KEY={}\n", f.value())
        };
        std::fs::write(&path, &original).unwrap();
        age(&path);
        let alias = f.home.home().join("hardlink");
        std::fs::hard_link(&path, &alias).unwrap();
        let out = f.scan(&["--yes", "--delete-plaintext"]);
        f.clean(&out);
        assert!(!out.status.success());
        let r: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(r["items"][0]["slug"], "openai/existing");
        let report = r["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["display_path"].as_str().unwrap().ends_with(source))
            .unwrap();
        assert!(
            report["kept"]
                .as_array()
                .unwrap()
                .iter()
                .any(|k| k["reason"] == "hard_link"),
            "{source}"
        );
        assert!(std::fs::read(&path).unwrap() == original.as_bytes());
        assert!(std::fs::read(&alias).unwrap() == original.as_bytes());
    }
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
    let mut command = on_terminal_command(&f.home, &args, &[(3, &pass, true)]);
    command.current_dir(outside.path());
    let restored = finish_within(command, Duration::from_secs(60));
    f.clean(&restored);
    assert!(restored.status.success());
    let statement = String::from_utf8_lossy(&restored.stderr);
    assert!(statement.contains(path.to_str().unwrap()));
    assert!(statement.contains("absolute paths"));
    assert!(statement.contains("overwritten only while it matches the recorded result"));
    assert!(!statement.contains("nothing is written anywhere else"));
    assert!(std::fs::read(&path).unwrap() == original.as_bytes());
}

#[test]
fn review_unrecorded_undo_statement_describes_overwriting_current_file() {
    let f = Fixture::new(true);
    let path = f.home.home().join(".zshrc");
    let original = format!("export OPENAI_API_KEY={}\n", f.value());
    std::fs::write(&path, &original).unwrap();
    age(&path);
    assert!(!paused(&f, "first_run_swapped", true, || {}).success());
    let list = envcloak_ipc::Client::connect(
        &envcloak_ipc::RunPaths::under(envcloak_testkit::daemon_run_dir(&f.home)).unwrap(),
    )
    .unwrap()
    .backup_v2_list()
    .unwrap();
    let id = &list.backups[0].id;
    std::fs::write(&path, b"# later edits are deliberately recovered over\n").unwrap();
    let refused = run_on_terminal(
        &f.home,
        &[
            "init",
            "--undo",
            id,
            "--created-by-agent",
            "--passphrase-fd",
            "3",
        ],
        &[],
    );
    f.clean(&refused);
    assert!(!refused.status.success());
    let statement = String::from_utf8_lossy(&refused.stderr);
    assert!(statement.contains("needs --unrecorded to overwrite the current file"));
    assert!(!statement.contains("only where a file is missing"));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"# later edits are deliberately recovered over\n"
    );
    let outside = outside_dir();
    let pass = secret_file(
        outside.path(),
        "pass",
        by_label(&f.values, labels::VAULT_PASSPHRASE).value(),
    );
    let restored = run_on_terminal(
        &f.home,
        &[
            "init",
            "--undo",
            id,
            "--unrecorded",
            "--created-by-agent",
            "--passphrase-fd",
            "3",
            "--json",
        ],
        &[(3, &pass, true)],
    );
    f.clean(&restored);
    assert!(restored.status.success());
    let statement = String::from_utf8_lossy(&restored.stderr);
    assert!(statement.contains(path.to_str().unwrap()));
    assert!(statement.contains("absolute paths"));
    assert!(statement.contains("overwrites the current file, including later edits"));
    assert!(!statement.contains("only where it is missing"));
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
