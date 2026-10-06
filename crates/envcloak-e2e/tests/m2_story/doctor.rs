//! M2-14, gate 36: CLI doctor on serializer-authored text, from a person
//! and an agent. The intentional input exposure is the sweep's positive control.
use envcloak_e2e::{Harness, target_dir};
use envcloak_testkit::labels;
use serde_json::Value;

#[test]
fn gate36_doctor_story() {
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
    let value = h.secret_file(labels::OPENAI_API_KEY, true);
    let added = h.human(
        &home,
        &["add", "openai", "--slug", "openai/doctor", "--stdin"],
        &[(0, &value, true)],
        &[],
    );
    assert_eq!(added.code, 0);
    let emitter = target_dir().join("ec-emit-serde");
    envcloak_testkit::assert_fresh(&emitter, "envcloak-e2e");
    let out = std::process::Command::new(emitter)
        .env_clear()
        .env(
            "FIXTURE",
            std::str::from_utf8(h.value(labels::OPENAI_API_KEY)).unwrap(),
        )
        .arg("FIXTURE")
        .output()
        .unwrap();
    assert!(out.status.success());
    let end = out.stdout.iter().position(|b| *b == 0).unwrap();
    let path = home.join(".claude/projects/doctor/transcript.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut encoded = out.stdout[..end].to_vec();
    encoded.push(b'\n');
    std::fs::write(&path, &encoded).unwrap();
    assert_eq!(h.sweep().len(), 1, "the input exposure must be detected");
    let person = h.human(&home, &["doctor", "--json"], &[], &[]);
    assert_eq!(person.code, 0);
    h.assert_clean("doctor person", person.all().as_bytes());
    let report: Value = serde_json::from_slice(&person.stdout).unwrap();
    assert_eq!(report["items"][0]["slug"], "openai/doctor");
    assert_eq!(report["items"][0]["places"][0]["count"], 1);
    let agent = h.agent(&home, &["doctor", "--json"]);
    assert!(agent.status.success());
    h.assert_clean("doctor agent", &agent.stdout);
    let report: Value = serde_json::from_slice(&agent.stdout).unwrap();
    assert_eq!(report["incomplete"], Value::Null);
    assert_eq!(report["items"][0]["slug"], "openai/doctor");
    assert_eq!(h.sweep().len(), 1, "doctor introduced another exposure");
}
