//! M2-21, gate 34: the person's terminal and the agent's refusal.
//! The separate Python observer measures the kernel PTY and reports raw
//! hit counts. Its stdout/stderr files are distinct from the PTY master.
use envcloak_e2e::Harness;
use envcloak_testkit::labels;

#[test]
fn gate34_reveal_story() {
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
        &["add", "openai", "--slug", "openai/reveal", "--stdin"],
        &[(0, &value, true)],
        &[],
    );
    assert_eq!(added.code, 0);
    #[cfg(target_os = "macos")]
    {
        let person = h.human(&home, &["reveal", "openai/reveal"], &[], &[]);
        assert_eq!(person.code, 125);
        assert!(person.err().starts_with("envcloak: app_required:"));
        assert!(person.tty.is_empty());
    }
    #[cfg(target_os = "linux")]
    {
        let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let spec = h.files().join("reveal.json");
        std::fs::write(
            &spec,
            serde_json::to_vec(&serde_json::json!({
                "value": hex(h.value(labels::OPENAI_API_KEY)),
                "proof": hex(h.value(labels::VAULT_PASSPHRASE)),
            }))
            .unwrap(),
        )
        .unwrap();
        let observer = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../envcloak-cli/tests/fixtures/reveal_terminal.py");
        let mut command = std::process::Command::new(envcloak_e2e::python3());
        let out = h
            .home
            .apply(&mut command)
            .arg(observer)
            .arg(&spec)
            .arg(h.cli())
            .args(["reveal", "openai/reveal"])
            .output()
            .unwrap();
        assert!(out.status.success());
        let o: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(o["code"], 0);
        assert_eq!(o["tty_hits"], 1);
        assert_eq!(o["control_hits"], 1);
        for field in [
            "stdout_hits",
            "stderr_hits",
            "proof_hits",
            "stdout_bytes",
            "stdout_leak_hits",
            "stderr_leak_hits",
            "proof_leak_hits",
        ] {
            assert_eq!(o[field], 0);
        }
        for field in ["warning", "waited", "echo_off", "restored"] {
            assert_eq!(o[field], true);
        }
        let agent = h.agent(&home, &["reveal", "openai/reveal"]);
        assert!(!agent.status.success());
        h.assert_clean("agent reveal stdout", &agent.stdout);
        h.assert_clean("agent reveal stderr", &agent.stderr);
    }
    h.assert_clean("reveal daemon", &h.daemon.log_bytes());
}
