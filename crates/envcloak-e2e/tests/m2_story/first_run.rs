//! M2-16: an isolated first run, with the actual CLI and daemon.
use envcloak_e2e::Harness;
use envcloak_testkit::labels;
use serde_json::Value;

#[test]
fn gate10_first_run_story() {
    let temporary = tempfile::tempdir_in("/tmp").unwrap();
    let mut h = Harness::start_with(&[("CLAUDE_CODE_TMPDIR", temporary.path().to_str().unwrap())]);
    let home = h.home.home();
    let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
    let kit = h.files().join("kit");
    let created = h.human(
        &home,
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
        &[],
    );
    assert_eq!(created.code, 0);
    std::fs::create_dir(home.join("app")).unwrap();
    let value = std::str::from_utf8(h.value(labels::OPENAI_API_KEY)).unwrap();
    let dotenv = format!("OPENAI_API_KEY={value}\n");
    std::fs::write(home.join("app/.env"), &dotenv).unwrap();
    let profile = format!("export OPENAI_API_KEY={value}\n");
    std::fs::write(home.join(".zshrc"), &profile).unwrap();
    let control = envcloak_testkit::find(profile.as_bytes(), &h.canaries);
    assert!(!control.is_empty());
    let dry = h.agent(&home, &["import", "--machine", "--json"]);
    assert!(dry.status.success());
    h.assert_clean("first run dry", &dry.stdout);
    assert!(!home.join("app/envcloak.toml").exists());
    let imported = h.agent(&home, &["import", "--machine", "--yes", "--json"]);
    assert!(imported.status.success());
    h.assert_clean("first run imported", &imported.stdout);
    let report: Value = serde_json::from_slice(&imported.stdout).unwrap();
    assert_eq!(report["schema"], "first_run.v1");
    assert_eq!(report["committed"], true);
    assert_eq!(report["items"].as_array().unwrap().len(), 1);
    assert_eq!(report["duplicates_merged"], 1);
    assert_eq!(report["items"][0]["scope"], "project");
    assert_eq!(report["items"][0]["owning_account"], "unknown");
    assert!(std::fs::read(home.join(".zshrc")).unwrap() == profile.as_bytes());
}
