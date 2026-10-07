//! g1, g4 and gates 19/22 against native signed peers, through the real daemon.
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used)]

#[test]
#[ignore = "requires scripts/macos/check-peer-code.sh and its disposable signing identities"]
fn native_app_peer_gates() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture = std::env::var_os("ENVCLOAK_PEER_FIXTURES").expect("native fixtures required");
    let result = std::process::Command::new("/usr/bin/python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", &fixture)
        .env(
            "ENVCLOAK_CLI_PROBE",
            std::env::var_os("ENVCLOAK_CLI_PROBE").expect("fresh CLI required"),
        )
        .arg(root.join("scripts/macos/tests/native_peer_gates.py"))
        .args(["app", env!("CARGO_BIN_EXE_envcloakd")])
        .arg(fixture)
        .status()
        .unwrap();
    assert!(result.success(), "native app peer gates failed");
}
