//! M2-12 transcript decoding, range, completeness and de-duplication gates.
#![allow(clippy::unwrap_used)]
use envcloak_core::SecretBytes;
use envcloak_scan::candidates::{Budget, Candidates, Encoding, Source};
use envcloak_scan::source::ConfigFormat;
use envcloak_scan::transcript::scan_reader;
use std::io::Cursor;

#[test]
fn json_escapes_keep_exact_raw_ranges_and_decoded_forms() {
    // Python, independent of the Rust parser, writes the escape syntax.
    let output=std::process::Command::new("/usr/bin/python3").args(["-I","-c","import json; print(json.dumps({'text':'abcdefghijklmno'+chr(233)+'xyz'},ensure_ascii=True))"])
        .env_clear().output().unwrap();
    assert!(output.status.success());
    let mut found = Vec::new();
    let report = scan_reader(
        &mut Cursor::new(&output.stdout),
        ConfigFormat::Jsonl,
        Source::default(),
        Budget::default(),
        &mut |c| {
            found.push(c);
            true
        },
    )
    .unwrap();
    assert!(report.complete());
    assert!(
        found
            .iter()
            .any(|c| c.value.ct_eq("abcdefghijklmnoéxyz".as_bytes()))
    );
    let c = found
        .iter()
        .find(|c| c.value.ct_eq("abcdefghijklmnoéxyz".as_bytes()))
        .unwrap();
    assert_eq!(
        &output.stdout[c.occurrence.range.start as usize..c.occurrence.range.end as usize],
        b"abcdefghijklmno\\u00e9xyz"
    );
    assert_eq!(c.occurrence.encoding, Encoding::Json);
    assert!(c.occurrence.rewritable);
}

#[test]
fn repeated_token_is_compared_once_with_every_occurrence() {
    let token = b"fixtureZvalueQrepeatedToken";
    let mut input = Vec::new();
    for _ in 0..100_000 {
        input.extend_from_slice(token);
        input.push(b' ');
    }
    let mut set = Candidates::new(Budget::default()).unwrap();
    let report = scan_reader(
        &mut Cursor::new(input),
        ConfigFormat::Raw,
        Source::default(),
        Budget::default(),
        &mut |c| set.insert(c),
    )
    .unwrap();
    assert!(report.complete());
    assert_eq!(set.entries().len(), 1);
    let entry = set.entries().iter().find(|c| c.value.ct_eq(token)).unwrap();
    assert_eq!(
        set.entries()
            .iter()
            .filter(|c| c.value.ct_eq(token))
            .count(),
        1
    );
    assert_eq!(entry.occurrences.len(), 100_000);
    assert_eq!(
        entry.occurrences[99_999].range.start,
        99_999 * (token.len() as u64 + 1)
    );
}

#[test]
fn stream_caps_and_malformed_input_never_report_complete() {
    let mut budget = Budget::default();
    budget.bytes = 31;
    let report = scan_reader(
        &mut Cursor::new(vec![b'z'; 100]),
        ConfigFormat::Raw,
        Source::default(),
        budget,
        &mut |_| true,
    )
    .unwrap();
    assert!(!report.complete());
    assert!(report.bytes <= 31);
    let report = scan_reader(
        &mut Cursor::new(b"{\"x\": \"unfinished\n{\"x\":\"fixtureZvalueQrepeatedToken\"}\n"),
        ConfigFormat::Jsonl,
        Source::default(),
        Budget::default(),
        &mut |_| true,
    )
    .unwrap();
    assert_eq!(report.not_scanned, 1);
    assert!(!report.complete());
    let mut set = Candidates::new(Budget {
        candidates: 0,
        ..Budget::default()
    })
    .unwrap();
    let report = scan_reader(
        &mut Cursor::new(b"fixtureZvalueQrepeatedToken"),
        ConfigFormat::Raw,
        Source::default(),
        Budget::default(),
        &mut |c| set.insert(c),
    )
    .unwrap();
    assert!(!report.complete());
    assert!(set.limited());
    drop(SecretBytes::copy_from(b"control"));
}

#[test]
fn encoded_tokens_keep_their_full_raw_span_without_claiming_rewrite() {
    let output=std::process::Command::new("/usr/bin/python3").args(["-I","-c","import base64,urllib.parse; v=b'fixtureZencodedValueWithSpaces'; print(base64.b64encode(v).decode()); print(v.hex()); print(''.join('%%%02X'%b for b in v)); print(base64.b64encode(b'prefix '+v+b' suffix').decode())"])
        .env_clear().output().unwrap();
    assert!(output.status.success());
    let mut found = Vec::new();
    let report = scan_reader(
        &mut Cursor::new(&output.stdout),
        ConfigFormat::Raw,
        Source::default(),
        Budget::default(),
        &mut |c| {
            found.push(c);
            true
        },
    )
    .unwrap();
    assert!(report.complete());
    assert_eq!(
        found
            .iter()
            .filter(|c| c.value.ct_eq(b"fixtureZencodedValueWithSpaces")
                && c.occurrence.encoding == Encoding::Base64)
            .count(),
        2
    );
    for encoding in [Encoding::Base64, Encoding::Hex, Encoding::Percent] {
        let c = found
            .iter()
            .find(|c| {
                c.value.ct_eq(b"fixtureZencodedValueWithSpaces")
                    && c.occurrence.encoding == encoding
            })
            .unwrap();
        assert!(!c.occurrence.rewritable);
        assert!(c.occurrence.range.end > c.occurrence.range.start);
        assert!(
            !output.stdout[c.occurrence.range.start as usize..c.occurrence.range.end as usize]
                .contains(&b'\n')
        );
    }
}

#[test]
fn repeated_assignment_separators_do_not_multiply_readings() {
    let mut bytes = b"A=".repeat(64);
    bytes.extend_from_slice(b"fixtureZassignmentValue");
    let mut raw = 0;
    let report = scan_reader(
        &mut Cursor::new(bytes),
        ConfigFormat::Raw,
        Source::default(),
        Budget::default(),
        &mut |c| {
            raw += usize::from(c.occurrence.encoding == Encoding::Raw);
            true
        },
    )
    .unwrap();
    assert!(report.complete());
    assert_eq!(raw, 2, "one token and one assignment reading");
}

#[test]
fn read_failure_retains_consumed_bytes_and_reports_partial() {
    struct Fails {
        read: bool,
    }
    impl std::io::Read for Fails {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.read {
                return Err(std::io::ErrorKind::Other.into());
            }
            self.read = true;
            out[..19].copy_from_slice(b"fixtureZreadValue \n");
            Ok(19)
        }
    }
    let report = scan_reader(
        &mut Fails { read: false },
        ConfigFormat::Raw,
        Source::default(),
        Budget::default(),
        &mut |_| true,
    )
    .expect("partial report retains its budget");
    assert_eq!(report.bytes, 19);
    assert!(!report.complete());
    assert!(report.issues.iter().any(|i| i.reason == "unreadable"));
}
