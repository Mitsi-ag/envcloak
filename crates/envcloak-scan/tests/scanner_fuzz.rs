//! Bounded parser fuzz targets; longer campaigns belong to milestone hardening.
#![allow(clippy::unwrap_used)]
use envcloak_core::SecretBytes;
use envcloak_scan::{
    agent_config::parse_config,
    candidates::{Budget, Source},
    profile::{Shell, parse_profile},
    source::ConfigFormat,
    transcript::scan_reader,
};
use proptest::prelude::*;

fn value_free(text: &str, marker: &str) -> bool {
    // Whole values and substantial fragments, without echoing a failed check.
    !marker
        .as_bytes()
        .windows(12)
        .any(|part| text.as_bytes().windows(part.len()).any(|s| s == part))
}

struct FailingReader(String);
impl std::io::Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other(self.0.clone()))
    }
}

proptest! {
    #![proptest_config(ProptestConfig {cases:128, failure_persistence:None, ..ProptestConfig::default()})]
    #[test]
    fn hostile_parser_bytes_are_bounded_and_errors_are_value_free(bytes in prop::collection::vec(any::<u8>(),0..16384)) {
        let marker = ["fixtureZdiagnostic", "privateMarker"].join("_");
        // The positive control checks the detector without publishing the value.
        prop_assert!(!value_free(&marker, &marker));
        let mut input = format!("A='{marker}'\n").into_bytes();
        input.extend_from_slice(&bytes);
        input.extend_from_slice(marker.as_bytes());
        let secret = SecretBytes::copy_from(&input);
        for shell in [Shell::Posix,Shell::Fish] {
            let r = parse_profile(&secret,shell);
            prop_assert!(value_free(&format!("{r:?}"), &marker), "diagnostic contains input");
            for i in &r.issues {prop_assert!(value_free(i.reason, &marker));}
            for f in r.findings {
                prop_assert!(f.range.start<=f.range.end&&f.range.end<=input.len() as u64);
                prop_assert!(value_free(&format!("{f:?}"), &marker), "finding contains input");
            }
        }
        for format in [ConfigFormat::Json,ConfigFormat::Toml,ConfigFormat::Yaml] {
            let r = parse_config(&secret,format);
            prop_assert!(value_free(&format!("{r:?}"), &marker), "diagnostic contains input");
            for i in &r.issues {prop_assert!(value_free(i.reason, &marker));}
        }
        for format in [ConfigFormat::Json,ConfigFormat::Jsonl,ConfigFormat::Raw] {
            let source = Source {path: marker.clone().into(), object:Some(marker.clone())};
            let r = scan_reader(&mut std::io::Cursor::new(&input),format,source.clone(),Budget {bytes:input.len() as u64 + 1,..Budget::default()},&mut |c| {
                assert!(c.occurrence.range.start<=c.occurrence.range.end&&c.occurrence.range.end<=input.len() as u64);
                assert!(value_free(&format!("{c:?}"), &marker), "candidate diagnostic contains input");
                true
            });
            prop_assert!(value_free(&format!("{r:?}"), &marker), "diagnostic contains input");
            match r {
                Ok(report) => for i in report.issues {prop_assert!(value_free(i.reason, &marker));},
                Err(error) => prop_assert!(value_free(&error.to_string(), &marker)),
            }
            let failure = scan_reader(&mut FailingReader(marker.clone()),format,source,Budget::default(),&mut |_| panic!("read failure emitted a value"));
            prop_assert!(value_free(&format!("{failure:?}"), &marker), "error diagnostic contains input");
            match failure {
                Ok(report) => {prop_assert!(!report.complete()); for i in report.issues {prop_assert!(value_free(i.reason, &marker));}},
                Err(error) => prop_assert!(value_free(&error.to_string(), &marker)),
            }
        }
    }
}

#[test]
fn hostile_parsers_keep_process_channels_value_free() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "hostile_parser_bytes_are_bounded_and_errors_are_value_free",
            "--nocapture",
            "--test-threads",
            "3",
        ])
        .env_clear()
        .env("HOME", d.path())
        .env("XDG_CONFIG_HOME", d.path())
        .env("TMPDIR", d.path())
        .env("RUST_LOG", "trace")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let marker = ["fixtureZdiagnostic", "privateMarker"].join("_");
    assert!(
        value_free(&String::from_utf8_lossy(&output.stdout), &marker),
        "stdout contains input"
    );
    assert!(
        value_free(&String::from_utf8_lossy(&output.stderr), &marker),
        "stderr contains input"
    );
    assert!(output.status.success(), "parser child failed");
}
