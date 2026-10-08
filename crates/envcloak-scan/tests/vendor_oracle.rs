//! Independent Cycle578 CSV writer and Cycle579 typed-schema expectations.
//! Documented format, not tool output. No vendor account or runtime claim.
#![allow(clippy::unwrap_used)]
use base64::Engine;
use envcloak_scan::formats::{self, Kind};
use std::process::Command;
#[test]
fn independent_csv_and_infisical_corpora_match_in_both_orders_and_all_chunks() {
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let output = Command::new("python3")
        .args(["-I", "-B"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/oracles/vendor_exports.py"
        ))
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/opt/homebrew/bin")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("XDG_DATA_HOME", home.path())
        .env("XDG_RUNTIME_DIR", home.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "independent emitter failed");
    let mut cases: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 120);
    for _ in 0..2 {
        for case in &cases {
            let id = case["id"].as_str().unwrap();
            let kind = Kind::parse(case["kind"].as_str().unwrap()).unwrap();
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(case["wire"].as_str().unwrap())
                .unwrap();
            for size in [1, 2, 7, 4096] {
                struct Chunks<'a>(&'a [u8], usize);
                impl std::io::Read for Chunks<'_> {
                    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                        let n = b.len().min(self.1).min(self.0.len());
                        b[..n].copy_from_slice(&self.0[..n]);
                        self.0 = &self.0[n..];
                        Ok(n)
                    }
                }
                let mut entries = Vec::new();
                let result = formats::parse(kind, Chunks(&bytes, size), &mut |e| entries.push(e));
                assert_eq!(
                    result.is_ok(),
                    case["ok"].as_bool().unwrap(),
                    "{id}: status"
                );
                let expected = case["entries"].as_array().unwrap();
                assert_eq!(entries.len(), expected.len(), "{id}: count");
                for (entry, want) in entries.iter().zip(expected) {
                    assert_eq!(
                        entry.record as u64,
                        want[0].as_u64().unwrap(),
                        "{id}: ordinal"
                    );
                    assert!(
                        entry.name.ct_eq(want[1].as_str().unwrap().as_bytes()),
                        "{id}: name"
                    );
                    assert!(
                        entry.value.ct_eq(want[2].as_str().unwrap().as_bytes()),
                        "{id}: value"
                    );
                }
            }
        }
        cases.reverse();
    }
}
