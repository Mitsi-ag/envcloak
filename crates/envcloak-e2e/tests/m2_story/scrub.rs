//! M2-22, gate 37: scrub and byte-exact undo through the real CLI and daemon.
use envcloak_e2e::Harness;
use envcloak_testkit::labels;
use serde_json::Value;
use std::time::{Duration, SystemTime};

#[test]
fn gate37_scrub_story() {
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
    let value = h.secret_file(labels::OPENAI_API_KEY, true);
    let added = h.human(
        &home,
        &["add", "openai", "--slug", "openai/scrub", "--stdin"],
        &[(0, &value, true)],
        &[],
    );
    assert_eq!(added.code, 0);
    let path = home.join(".claude/projects/scrub/events.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let before = format!(
        "{}\n",
        serde_json::json!({"text":std::str::from_utf8(h.value(labels::OPENAI_API_KEY)).unwrap()})
    );
    std::fs::write(&path, &before).unwrap();
    assert_eq!(h.sweep().len(), 1, "exposure detector positive control");
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(300))
        .unwrap();
    let out = h.human(
        &home,
        &["scrub", "--path", path.to_str().unwrap(), "--yes", "--json"],
        &[],
        &[],
    );
    assert_eq!(out.code, 0);
    h.assert_clean("scrub", out.all().as_bytes());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["files"][0]["state"], "scrubbed");
    assert!(h.sweep().is_empty(), "scrub left an exposure");
    let id = report["files"][0]["backup"].as_str().unwrap();
    let restored = h.human(
        &home,
        &["scrub", "--undo", id, "--passphrase-fd", "3", "--json"],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(restored.code, 0);
    h.assert_clean("scrub undo", restored.all().as_bytes());
    assert!(std::fs::read(&path).unwrap() == before.as_bytes());
    assert_eq!(
        h.sweep().len(),
        1,
        "undo exposure is exactly the original file"
    );
}
