//! Heap wipe evidence for enrollment success, partial-decode failure,
//! late parameter failure and code generation. This is not a stack scan.
#![allow(clippy::unwrap_used)]

use envcloak_core::SecretBytes;
use envcloak_signin::{otpauth, totp};
use envcloak_testkit::{ProbeAllocator, ProbeMode, ProbeSession};
use serde_json::Value;

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

fn bytes(row: &Value, field: &str) -> Vec<u8> {
    row[field]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect()
}

#[test]
fn seed_decoding_and_code_buffers_wipe_on_every_exit() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracles/totp-cases.json");
    let rows: Vec<Value> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut controls = 0;
    // All algorithms and widths, long seeds straddling HMAC block sizes.
    for row in rows
        .iter()
        .filter(|r| r["id"].as_str().unwrap().starts_with("random-"))
        .step_by(12)
    {
        let seed = bytes(row, "seed");
        let base32 = bytes(row, "base32");
        let expected = bytes(row, "expected_code");
        let step = row["step"].as_str().unwrap().parse().unwrap();
        let algorithm = match row["algorithm"].as_str().unwrap() {
            "sha1" => (totp::Algorithm::Sha1, "SHA1"),
            "sha256" => (totp::Algorithm::Sha256, "SHA256"),
            "sha512" => (totp::Algorithm::Sha512, "SHA512"),
            _ => panic!("invalid fixture"),
        };
        let width = row["digits"].as_u64().unwrap() as u8;
        let suffix = format!("&algorithm={}&digits={width}&period=30", algorithm.1);
        let mut raw = b"otpauth://totp/fixture?secret=".to_vec();
        raw.extend_from_slice(&base32);
        raw.extend_from_slice(suffix.as_bytes());
        let mut late_error = raw.clone();
        late_error.extend_from_slice(b"&period=0");
        let mut decode_error = b"otpauth://totp/fixture?secret=".to_vec();
        decode_error.extend_from_slice(&base32);
        // Same length, invalid final character, after most bytes decoded.
        *decode_error.last_mut().unwrap() = b'0';
        let needles = [&seed[..], &base32[..], &expected[..]];

        let session = ProbeSession::start(&needles, 16, ProbeMode::Unwiped);
        drop(std::hint::black_box(seed.clone()));
        drop(std::hint::black_box(base32.clone()));
        drop(std::hint::black_box(expected.clone()));
        let positive = session.finish();
        assert!(positive.released_with_needle >= 3, "{positive:?}");
        controls += positive.released_with_needle;

        let session = ProbeSession::start(&needles, 16, ProbeMode::Unwiped);
        let spec = otpauth::parse(&SecretBytes::copy_from(&raw)).unwrap();
        let code = totp::code(spec.seed(), spec.params(), step);
        assert!(code.as_secret().ct_eq(&expected), "code comparison failed");
        drop(code);
        drop(spec);
        assert!(otpauth::parse(&SecretBytes::copy_from(&late_error)).is_err());
        assert!(otpauth::parse(&SecretBytes::copy_from(&decode_error)).is_err());
        let report = session.finish();
        assert_eq!(report.released_with_needle, 0, "{report:?}");
    }
    assert!(controls >= 180, "probe positive controls missing");
}
