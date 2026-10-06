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
use std::os::unix::fs::PermissionsExt;

fn bundle() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ec-codex-transcript-oracle-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .unwrap()
}

fn oracle() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracles/transcript_ranges.py")
}

fn generate(root: &std::path::Path) -> std::process::Output {
    std::process::Command::new("/usr/bin/python3")
        .arg("-I")
        .arg(oracle())
        .arg(root)
        .env_clear()
        .env("HOME", root)
        .output()
        .unwrap()
}

fn failure_reason(stderr: &[u8]) -> &'static str {
    match stderr {
        b"oracle_failed:bundle_location\n" => "bundle_location",
        b"oracle_failed:bundle_name\n" => "bundle_name",
        b"oracle_failed:bundle_owner\n" => "bundle_owner",
        b"oracle_failed:bundle_mode\n" => "bundle_mode",
        b"oracle_failed:bundle_nonempty\n" => "bundle_nonempty",
        b"oracle_failed:bundle_marker\n" => "bundle_marker",
        b"oracle_failed:internal\n" => "internal",
        _ => "oracle_failed",
    }
}

#[test]
fn range_oracle_failures_report_only_fixed_codes() {
    let dir = bundle();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = generate(dir.path());
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        output.stderr == b"oracle_failed:bundle_mode\n",
        "mode refusal did not return its fixed reason"
    );
    assert_eq!(failure_reason(&output.stderr), "bundle_mode");

    let output = std::process::Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-c",
            r#"
import runpy, sys
code = runpy.run_path(sys.argv[1])["failure_code"]
marker = "".join(("fixtureZ", "privateDiagnostic"))
for error in [ValueError("bundle_mode"), ValueError(marker),
              ValueError("bundle_mode", marker), OSError(marker),
              AssertionError(marker)]:
    print(code(error))
"#,
        ])
        .arg(oracle())
        .env_clear()
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "reason-code probe failed");
    assert!(
        output.stderr.is_empty(),
        "reason-code probe wrote diagnostics"
    );
    assert!(
        output.stdout == b"bundle_mode\ninternal\ninternal\ninternal\ninternal\n",
        "reason-code probe returned non-static diagnostics"
    );
    assert_eq!(
        failure_reason(b"oracle_failed:fixtureZprivateDiagnostic\n"),
        "oracle_failed"
    );
}

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
    let d = bundle();
    let output = generate(d.path());
    assert!(
        output.status.success(),
        "range oracle generation failed: {}",
        failure_reason(&output.stderr)
    );
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
            let mut matching_occurrences = 0;
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
                    matching_occurrences += 1;
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
            observed.insert(
                case["id"].as_str().unwrap().to_owned(),
                (distinct, matching_occurrences, spans),
            );
        }
        let expected: serde_json::Value =
            serde_json::from_slice(&std::fs::read(d.path().join("expected.json")).unwrap())
                .unwrap();
        for case in expected["cases"].as_array().unwrap() {
            let (distinct, matching_occurrences, spans) =
                observed.remove(case["id"].as_str().unwrap()).unwrap();
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
            assert_eq!(
                matching_occurrences,
                case["count"].as_u64().unwrap() as usize
            );
            assert_eq!(spans.len(), matching_occurrences);
            assert!(spans == wanted, "independent ranges differ");
        }
        assert!(observed.is_empty());
    }
}
