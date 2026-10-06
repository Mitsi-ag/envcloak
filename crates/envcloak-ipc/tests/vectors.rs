//! Cross-language M3-03 fixtures. The values are runtime canaries and the
//! encoders are the real Rust frame, WireSecret and display implementations.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{fs, io::Write, path::Path};

use envcloak_core::SecretBytes;
use envcloak_ipc::{ErrorKind, Frame, WireSecret, proto::REASONS};
use envcloak_testkit::{canaries, fresh_seed};
use serde_json::json;

#[test]
fn swift_cross_language_vectors() {
    let temporary = tempfile::tempdir().unwrap();
    let explicit = std::env::var_os("ENVCLOAK_SWIFT_VECTORS");
    let directory = explicit.as_deref().map(Path::new).unwrap_or(temporary.path());
    let metadata = fs::symlink_metadata(directory).unwrap();
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    let mut values = Vec::new();
    for canary in canaries(fresh_seed()) {
        let value = WireSecret::new(SecretBytes::copy_from(canary.value()));
        let frame = Frame::encode(&value).unwrap();
        let mut encoded = Vec::new();
        frame.write_to(&mut encoded).unwrap();
        let decoded: WireSecret = Frame::read_from(&mut encoded.as_slice())
            .unwrap()
            .decode()
            .unwrap();
        assert!(decoded.as_secret().ct_eq(canary.value()));
        values.push(json!({"bytes": canary.value(), "frame": encoded}));
    }
    // Padding and the 16 KiB growth boundary, generated without literals.
    for length in [0, 1, 2, 3, 16_383, 16_384, 16_385] {
        let bytes: Vec<u8> = (0..length).map(|n| (n % 256) as u8).collect();
        let value = WireSecret::new(SecretBytes::copy_from(&bytes));
        let mut encoded = Vec::new();
        Frame::encode(&value).unwrap().write_to(&mut encoded).unwrap();
        values.push(json!({"bytes": bytes, "frame": encoded}));
    }
    let escapes: Vec<_> = (0..=0x10ffff)
        .filter_map(char::from_u32)
        .filter(|c| envcloak_policy::display_escaped(*c) || *c == '\\')
        .map(|c| {
            let text = format!("a{c}z");
            json!({"input": text, "display": envcloak_policy::escape_for_display(&text)})
        })
        .collect();
    let errors: Vec<_> = ErrorKind::ALL
        .iter()
        .map(|kind| json!({"kind": kind.token(), "code": kind.code()}))
        .collect();
    let output = json!({"base64": values, "escapes": escapes, "reasons": REASONS, "errors": errors});
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("rust.json"))
        .unwrap();
    file.write_all(&serde_json::to_vec(&output).unwrap()).unwrap();
    file.sync_all().unwrap();
}
