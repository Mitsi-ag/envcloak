//! Shared helpers for the daemon's integration tests.
#![allow(dead_code, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use envcloak_core::{RecoveryKit, SecretBytes};
use envcloak_ipc::{Client, RunPaths};
use envcloak_testkit::{Canary, Daemon, TestHome, by_label, daemon_run_dir, labels};

/// Argon2id memory for test vaults: the 64 MiB floor.
pub const TEST_KDF_KIB: u32 = 64 * 1024;

pub fn exe() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_envcloakd"))
}

pub fn run_paths(home: &TestHome) -> RunPaths {
    RunPaths::under(daemon_run_dir(home)).unwrap()
}

pub fn start(home: &TestHome) -> Daemon {
    Daemon::start(home, exe(), &[])
}

pub fn client(home: &TestHome) -> Client {
    Client::connect(&run_paths(home)).unwrap()
}

pub fn passphrase(cs: &[Canary]) -> SecretBytes {
    SecretBytes::copy_from(by_label(cs, labels::VAULT_PASSPHRASE).value())
}

/// Creates the vault with the canary passphrase and a new kit, whose text
/// is returned as a canary to sweep for.
pub fn create_vault(home: &TestHome, cs: &[Canary]) -> Canary {
    let kit = RecoveryKit::generate();
    let text = kit.to_display();
    let mut c = client(home);
    let v = c
        .vault_create(
            passphrase(cs),
            SecretBytes::copy_from(text.as_bytes()),
            Some(TEST_KDF_KIB),
        )
        .unwrap();
    assert!(!v.already);
    Canary::new("RECOVERY_KIT", text.to_string())
}

/// A raw connection to the daemon, for frames no client would send.
pub fn raw(home: &TestHome) -> UnixStream {
    let s = UnixStream::connect(run_paths(home).socket).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s
}

/// Sends `v` as one frame.
pub fn send_json(s: &mut UnixStream, v: &serde_json::Value) {
    let body = serde_json::to_vec(v).unwrap();
    s.write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
        .unwrap();
    s.write_all(&body).unwrap();
}

/// Reads one response frame as JSON, or `None` at end of stream.
pub fn read_json(s: &mut UnixStream) -> Option<serde_json::Value> {
    let mut header = [0u8; 4];
    if s.read_exact(&mut header).is_err() {
        return None;
    }
    let mut body = vec![0u8; u32::from_be_bytes(header) as usize];
    s.read_exact(&mut body).unwrap();
    Some(serde_json::from_slice(&body).unwrap())
}

/// The `data.kind` token of an error response.
pub fn error_kind(v: &serde_json::Value) -> String {
    v["error"]["data"]["kind"]
        .as_str()
        .unwrap_or_else(|| panic!("not an error response: {v}"))
        .to_owned()
}

/// Whether the peer closed the connection: a read returns end of stream.
pub fn closed(s: &mut UnixStream) -> bool {
    let mut b = [0u8; 1];
    matches!(s.read(&mut b), Ok(0))
}

/// Resident memory of `pid` in KiB, from `ps`.
pub fn rss_kib(pid: i32) -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}
