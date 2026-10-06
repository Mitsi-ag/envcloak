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

fn enrollment(secret: &[u8]) -> Vec<u8> {
    let mut raw = b"otpauth://totp/fixture?secret=".to_vec();
    raw.extend_from_slice(secret);
    raw
}

fn check_release(raw: &[u8], needle: &[u8], accepted: bool, case: &str) {
    assert!(!needle.is_empty(), "empty wipe oracle");
    let session = ProbeSession::start(&[needle], needle.len(), ProbeMode::Unwiped);
    drop(std::hint::black_box(needle.to_vec()));
    let control = session.finish();
    assert_eq!(control.released_with_needle, 1, "{case}: {control:?}");

    let session = ProbeSession::start(&[needle], needle.len(), ProbeMode::Unwiped);
    let result = otpauth::parse(&SecretBytes::copy_from(raw));
    let correct = match &result {
        Ok(spec) => accepted && spec.seed().ct_eq(needle),
        Err(_) => !accepted,
    };
    drop(result);
    let report = session.finish();
    assert!(correct, "{case}: unexpected parse result");
    assert_eq!(report.released_with_needle, 0, "{case}: {report:?}");
}

fn short_and_partial_decoding() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/oracles/totp-decoding-cases.json");
    let rows: Vec<Value> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(rows.len(), 32);
    for (index, row) in rows.iter().enumerate() {
        let seed = bytes(row, "seed");
        let base32 = bytes(row, "base32");
        assert_eq!(seed.len(), index + 1);
        for encoded in [&base32, &base32.to_ascii_lowercase()] {
            check_release(&enrollment(encoded), &seed, true, "short success");
        }
        let mut late_error = enrollment(&base32);
        late_error.extend_from_slice(b"&period=0");
        check_release(&late_error, &seed, false, "short late failure");
        // Every character position, including prefixes shorter than 16 bytes.
        // Keep the length valid so the decoder reaches the invalid symbol.
        for at in 0..base32.len() {
            let mut damaged = base32.clone();
            damaged[at] = b'0';
            let prefix = &seed[..at * 5 / 8];
            let raw = enrollment(&damaged);
            if prefix.is_empty() {
                assert!(otpauth::parse(&SecretBytes::copy_from(&raw)).is_err());
            } else {
                check_release(&raw, prefix, false, "base32 partial failure");
            }
        }
        let bad_tail = bytes(row, "bad_tail");
        if !bad_tail.is_empty() {
            check_release(&enrollment(&bad_tail), &seed, false, "base32 tail failure");
        }
        // decode() is shared by labels and every parameter, not just seeds.
        let escaped = bytes(row, "percent");
        for field in ["label", "secret", "issuer", "algorithm", "digits", "period"] {
            for ending in [b"%".as_slice(), b"%0", b"%0g", b"%g0", b"!", b"%00"] {
                let mut value = escaped.clone();
                value.extend_from_slice(ending);
                let mut raw = if field == "label" {
                    b"otpauth://totp/".to_vec()
                } else {
                    format!("otpauth://totp/fixture?{field}=").into_bytes()
                };
                raw.extend_from_slice(&value);
                if field == "label" {
                    raw.extend_from_slice(b"?secret=");
                    raw.extend_from_slice(&base32);
                }
                check_release(&raw, &seed, false, "percent partial failure");
            }
        }
    }
}

#[test]
fn seed_decoding_and_code_buffers_wipe_on_every_exit() {
    // Keep all probes in this one test: their allocator observes all threads.
    short_and_partial_decoding();
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
        let report = session.finish();
        assert_eq!(report.released_with_needle, 0, "{report:?}");

        // Retain the original long-seed failure samples with a needle that
        // describes what was decoded, including the 15-byte prefixes.
        let mut damaged = base32.clone();
        *damaged.last_mut().unwrap() = b'0';
        let prefix = &seed[..(base32.len() - 1) * 5 / 8];
        check_release(
            &enrollment(&damaged),
            prefix,
            false,
            "long base32 partial failure",
        );
    }
    assert!(controls >= 180, "probe positive controls missing");
}
