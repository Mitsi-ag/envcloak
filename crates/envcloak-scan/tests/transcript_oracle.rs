//! Independent cycle432 JSON/encoding/range oracle. This is not a scrub test.
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]
use envcloak_scan::{
    candidates::{Budget, Candidates, Encoding},
    source::ConfigFormat,
    transcript::scan_reader,
};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

type Spans = BTreeSet<(u64, u64, String, String)>;
struct Chunked<R> {
    reader: R,
    size: usize,
}
impl<R: Read> Read for Chunked<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = out.len().min(self.size);
        self.reader.read(&mut out[..n])
    }
}

#[test]
fn independent_json_ranges_and_duplicate_occurrences_match_in_small_chunks() {
    let d = tempfile::Builder::new()
        .prefix("ec-codex-transcript-oracle-")
        .tempdir_in("/tmp")
        .unwrap();
    let output = std::process::Command::new("/usr/bin/python3")
        .arg("-I")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/oracles/transcript_ranges.py"),
        )
        .arg(d.path())
        .env_clear()
        .env("HOME", d.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "range oracle generation failed");
    assert!(output.stderr.is_empty());
    let counts: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(counts["cases"], 37);
    assert_eq!(counts["ranges"], 100080);
    let requests: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.path().join("requests.json")).unwrap()).unwrap();
    for chunk in [32768, 7] {
        let mut observed = BTreeMap::new();
        // Produce observations from requests and inputs only, before loading
        // the generator's independent expected ranges. No preview is invented.
        for case in requests["cases"].as_array().unwrap() {
            let matches = case["matches"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["digest"].as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>();
            let mut set = Candidates::new(Budget::default()).unwrap();
            let mut reader = Chunked {
                reader: std::fs::File::open(d.path().join(case["input"].as_str().unwrap()))
                    .unwrap(),
                size: chunk,
            };
            let report = scan_reader(
                &mut reader,
                ConfigFormat::Jsonl,
                Default::default(),
                Budget::default(),
                &mut |c| set.insert(c),
            )
            .unwrap();
            assert!(report.complete() && !set.limited());
            let mut spans = Spans::new();
            let mut distinct = 0;
            for entry in set.entries() {
                let digest = Sha256::digest(entry.value.expose_secret())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                if !matches.contains(&digest) {
                    continue;
                }
                distinct += 1;
                for o in &entry.occurrences {
                    let form = match o.encoding {
                        Encoding::Raw | Encoding::Json => "raw",
                        Encoding::Base64 => "base64",
                        Encoding::Hex => "hex",
                        Encoding::Percent => "percent",
                    };
                    if matches!(
                        o.encoding,
                        Encoding::Base64 | Encoding::Hex | Encoding::Percent
                    ) {
                        assert!(!o.rewritable);
                    }
                    spans.insert((o.range.start, o.range.end, form.to_owned(), digest.clone()));
                }
            }
            observed.insert(case["id"].as_str().unwrap().to_owned(), (distinct, spans));
        }
        let expected: serde_json::Value =
            serde_json::from_slice(&std::fs::read(d.path().join("expected.json")).unwrap())
                .unwrap();
        for case in expected["cases"].as_array().unwrap() {
            let (distinct, spans) = observed.remove(case["id"].as_str().unwrap()).unwrap();
            let wanted = case["occurrences"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    (
                        v["start"].as_u64().unwrap(),
                        v["end"].as_u64().unwrap(),
                        v["form"].as_str().unwrap().to_owned(),
                        v["digest"].as_str().unwrap().to_owned(),
                    )
                })
                .collect::<Spans>();
            assert_eq!(distinct, case["distinct"].as_u64().unwrap() as usize);
            assert_eq!(spans.len(), case["count"].as_u64().unwrap() as usize);
            assert!(spans == wanted, "independent ranges differ");
        }
        assert!(observed.is_empty());
    }
}
