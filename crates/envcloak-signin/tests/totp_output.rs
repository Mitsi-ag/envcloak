//! A harness-free fixture lets an independent process observe both streams.
#![allow(clippy::unwrap_used)]

use envcloak_core::SecretBytes;
use envcloak_signin::{otpauth, totp};
use serde_json::Value;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bytes(row: &Value, field: &str) -> Vec<u8> {
    row[field]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect()
}

fn fixture() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let rows: Vec<Value> =
        serde_json::from_slice(&std::fs::read(root.join("tests/oracles/totp-cases.json")).unwrap())
            .unwrap();
    for row in rows {
        let mut raw = b"otpauth://totp/fixture?secret=".to_vec();
        raw.extend(bytes(&row, "base32"));
        let algorithm = match row["algorithm"].as_str().unwrap() {
            "sha1" => "SHA1",
            "sha256" => "SHA256",
            "sha512" => "SHA512",
            _ => panic!("invalid fixture algorithm"),
        };
        raw.extend(format!("&algorithm={algorithm}&digits={}", row["digits"]).bytes());
        let spec = otpauth::parse(&SecretBytes::copy_from(&raw)).unwrap();
        let code = totp::code(
            spec.seed(),
            spec.params(),
            row["step"].as_str().unwrap().parse().unwrap(),
        );
        assert!(
            code.as_secret().ct_eq(&bytes(&row, "expected_code")),
            "fixture calculation failed"
        );
        std::hint::black_box(format!(
            "{spec:?} {spec} {code:?} {code} {:?}",
            spec.params()
        ));
        std::hint::black_box(format!(
            "{:?} {:?} {:?} {:?} {:?} {}",
            totp::Algorithm::Sha1,
            totp::Algorithm::Sha256,
            totp::Algorithm::Sha512,
            spec.params().period(),
            totp::ParamsError,
            totp::ParamsError
        ));
        for suffix in [b"&period=0".as_slice(), b"&unknown=1", b"&secret=bad"] {
            let mut invalid = raw.clone();
            invalid.extend(suffix);
            let error = otpauth::parse(&SecretBytes::copy_from(&invalid))
                .err()
                .expect("invalid fixture accepted");
            std::hint::black_box(format!("{error:?} {error}"));
        }
    }
}

fn main() {
    if std::env::args().any(|a| a == "--fixture") {
        fixture();
        return;
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut child = Command::new("python3")
        .args(["-I", "-B"])
        .arg(root.join("tests/oracles/totp_output.py"))
        .arg(std::env::current_exe().unwrap())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", std::env::temp_dir())
        .env("TMPDIR", std::env::temp_dir())
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .spawn()
        .expect("output oracle unavailable");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.try_wait().expect("output oracle wait failed") {
            assert!(status.success(), "TOTP output gate failed");
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("cannot stop owned output oracle");
            child.wait().expect("cannot reap output oracle");
            panic!("TOTP output oracle timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
