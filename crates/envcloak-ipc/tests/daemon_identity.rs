//! g1 and gate 21: a wrong daemon receives zero bytes, a pinned one receives a frame.
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used)]

#[test]
#[ignore = "requires scripts/macos/check-peer-code.sh and its disposable signing identities"]
fn native_daemon_identity_gate() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture = std::env::var_os("ENVCLOAK_PEER_FIXTURES").expect("native fixtures required");
    let probe = std::env::var_os("ENVCLOAK_IDENTITY_PROBE").expect("fresh IPC example required");
    let result = std::process::Command::new("/usr/bin/python3")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", &fixture)
        .arg(root.join("scripts/macos/tests/native_peer_gates.py"))
        .arg("client")
        .arg(probe)
        .arg(fixture)
        .status()
        .unwrap();
    assert!(result.success(), "native daemon identity gate failed");
}
