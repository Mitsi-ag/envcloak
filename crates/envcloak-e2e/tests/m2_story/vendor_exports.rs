//! M2-23: export and project imports share the daemon's dedupe path.
//! Fixture: documented format, not tool output.
use envcloak_e2e::Harness;
use envcloak_testkit::labels;
use serde_json::{Value, json};
#[test]
fn gate10_vendor_export_story() {
    let mut h = Harness::start();
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
    let value = std::str::from_utf8(h.value(labels::OPENAI_API_KEY)).unwrap();
    let export = home.join("export.json");
    let bytes = serde_json::to_vec(&json!({"SERVICE_TOKEN":value})).unwrap();
    assert!(!envcloak_testkit::find(&bytes, &h.canaries).is_empty());
    std::fs::write(&export, &bytes).unwrap();
    let project = home.join("app");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join(".env"), format!("SERVICE_TOKEN={value}\n")).unwrap();
    let out = h.agent(
        &home,
        &[
            "import",
            "--from",
            "doppler-json",
            export.to_str().unwrap(),
            "--yes",
            "--json",
        ],
    );
    assert!(out.status.success());
    h.assert_clean("export stdout", &out.stdout);
    h.assert_clean("export stderr", &out.stderr);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["imported_entries"], 1);
    assert_eq!(report["items"][0]["scope"], "machine");
    assert_eq!(report["provenance"], "unknown");
    let out = h.agent(
        &home,
        &[
            "import",
            "--scan",
            project.to_str().unwrap(),
            "--yes",
            "--json",
        ],
    );
    assert!(out.status.success());
    h.assert_clean("project import", &out.stdout);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["items"].as_array().unwrap().len(), 1);
    assert_eq!(report["items"][0]["existing"], true);
    assert!(std::fs::read(export).unwrap() == bytes);
}
