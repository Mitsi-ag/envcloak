//! Exact matches must survive presentation punctuation without losing spans.
#![allow(clippy::unwrap_used)]
use envcloak_scan::{
    candidates::{Budget, Encoding, Form},
    source::ConfigFormat,
    transcript::scan_reader,
};

#[test]
fn raw_and_json_wrappings_preserve_candidates_and_ranges() {
    let value = "fixtureZwrappedValue";
    for text in [
        format!(" {value} "),
        format!("`{value}`"),
        format!("{value}."),
        format!("({value})"),
        format!("--api-key={value}"),
        format!("https://h/?k={value}&z=1"),
        format!("TOKEN:{value}"),
        format!("**{value}**"),
        format!("|{value}|"),
        format!("'{value}'"),
        format!("[{value}]"),
    ] {
        for format in [ConfigFormat::Raw, ConfigFormat::Jsonl] {
            let input = if format == ConfigFormat::Jsonl {
                serde_json::to_vec(&text).unwrap()
            } else {
                text.as_bytes().to_vec()
            };
            let mut found = false;
            let r = scan_reader(
                &mut std::io::Cursor::new(&input),
                format,
                Default::default(),
                Budget::default(),
                &mut |c| {
                    if c.value.ct_eq(value.as_bytes()) {
                        found = true;
                        let range = c.occurrence.range;
                        assert_eq!(
                            &input[range.start as usize..range.end as usize],
                            value.as_bytes()
                        );
                    }
                    true
                },
            )
            .unwrap();
            assert!(r.complete(), "{r:?}");
            assert!(found, "missing wrapping {text}");
        }
    }
}

#[test]
fn punctuation_inside_values_and_decoded_wrappings_stay_intact() {
    use base64::Engine;
    for punctuation in [",", ";", "'", "\"", "{", "}", "[", "]", "<", ">", "=", ":"] {
        let value = format!("fixtureZleft{punctuation}rightValue");
        for format in [ConfigFormat::Raw, ConfigFormat::Jsonl] {
            let input = if format == ConfigFormat::Jsonl {
                serde_json::to_vec(&value).unwrap()
            } else {
                value.as_bytes().to_vec()
            };
            let mut found = false;
            let r = scan_reader(
                &mut std::io::Cursor::new(input),
                format,
                Default::default(),
                Budget::default(),
                &mut |c| {
                    found |= c.value.ct_eq(value.as_bytes());
                    true
                },
            )
            .unwrap();
            assert!(r.complete());
            assert!(found);
        }
    }
    let value = b"fixtureZencodedWrappedValue";
    let mut wrapped = vec![b'`'];
    wrapped.extend_from_slice(value);
    wrapped.push(b'`');
    let encoded = base64::engine::general_purpose::STANDARD.encode(wrapped);
    let mut found = false;
    let r = scan_reader(
        &mut std::io::Cursor::new(encoded.as_bytes()),
        ConfigFormat::Raw,
        Default::default(),
        Budget::default(),
        &mut |c| {
            if c.value.ct_eq(value) {
                found = true;
                assert!(!c.occurrence.rewritable);
                assert_eq!(c.occurrence.encoding, Encoding::Base64);
            }
            true
        },
    )
    .unwrap();
    assert!(r.complete());
    assert!(found);
}

#[test]
fn password_readings_keep_their_forms_and_raw_locations() {
    let value = "fixtureZpasswordValue";
    for (text, form) in [
        (format!("https://user:{value}@host/path"), Form::UrlPassword),
        (format!("user:{value}@tcp(host)/db"), Form::DsnPassword),
        (format!("user:{value}@/db"), Form::DsnPassword),
        (format!("Password={value};Host=db"), Form::ConnPassword),
        (format!("password='{value}';"), Form::ConnPassword),
        (format!("pwd={{{value}}};"), Form::ConnPassword),
    ] {
        let mut found = false;
        let r = scan_reader(
            &mut std::io::Cursor::new(text.as_bytes()),
            ConfigFormat::Raw,
            Default::default(),
            Budget::default(),
            &mut |c| {
                if c.value.ct_eq(value.as_bytes()) {
                    assert_ne!(c.form, Form::Raw, "password reading lost its context");
                }
                if c.value.ct_eq(value.as_bytes()) && c.form == form {
                    found = true;
                    let range = c.occurrence.range;
                    assert_eq!(
                        &text.as_bytes()[range.start as usize..range.end as usize],
                        value.as_bytes()
                    );
                }
                true
            },
        )
        .unwrap();
        assert!(r.complete());
        assert!(found, "missing form {form:?}");
    }
}

#[test]
fn binary_boundaries_preserve_text_and_reading_caps_report_partial() {
    let mut input = vec![0xff, 0xfe];
    input.extend_from_slice(b"fixtureZbinaryAdjacentValue");
    input.push(0xff);
    let mut found = false;
    let r = scan_reader(
        &mut std::io::Cursor::new(input),
        ConfigFormat::Raw,
        Default::default(),
        Budget::default(),
        &mut |c| {
            found |= c.value.ct_eq(b"fixtureZbinaryAdjacentValue");
            true
        },
    )
    .unwrap();
    assert!(found);
    assert!(!r.complete());
    assert!(r.not_scanned > 0);
    let input = "fixtureZvalueLongEnough:".repeat(160);
    let r = scan_reader(
        &mut std::io::Cursor::new(input),
        ConfigFormat::Raw,
        Default::default(),
        Budget {
            occurrences: 3,
            ..Budget::default()
        },
        &mut |_| true,
    )
    .unwrap();
    assert!(!r.complete());
    assert!(
        r.issues
            .iter()
            .any(|i| matches!(i.reason, "occurrence_budget" | "reading_budget"))
    );
}

#[test]
fn mixed_json_encodings_do_not_claim_the_whole_message() {
    let value = "fixtureZmixedEncodingValue";
    let percent: String = value.bytes().map(|b| format!("%{b:02X}")).collect();
    let text = format!("prefix {value} between {percent} suffix");
    let input = serde_json::to_vec(&text).unwrap();
    let mut found = Vec::new();
    let report = scan_reader(
        &mut std::io::Cursor::new(&input),
        ConfigFormat::Jsonl,
        Default::default(),
        Budget::default(),
        &mut |c| {
            if c.value.ct_eq(value.as_bytes()) {
                found.push(c.occurrence);
            }
            true
        },
    )
    .unwrap();
    assert!(report.complete());
    assert_eq!(found.len(), 2);
    for occurrence in found {
        let span = &input[occurrence.range.start as usize..occurrence.range.end as usize];
        match occurrence.encoding {
            Encoding::Json => assert_eq!(span, value.as_bytes()),
            Encoding::Percent => assert_eq!(span, percent.as_bytes()),
            other => panic!("unexpected reading {other:?}"),
        }
    }
}

#[test]
fn base64_padding_stays_in_each_wrapped_raw_range() {
    use base64::Engine;
    for width in [23, 25] {
        let value = &"fixtureZvaluePaddedForOracle"[..width];
        let encoded = base64::engine::general_purpose::STANDARD.encode(value);
        assert!(encoded.ends_with('='));
        for text in [
            format!("prefix {encoded} suffix"),
            format!("`{encoded}`"),
            format!("({encoded})"),
            format!("{encoded}."),
        ] {
            let input = serde_json::to_vec(&text).unwrap();
            let mut found = Vec::new();
            let report = scan_reader(
                &mut std::io::Cursor::new(&input),
                ConfigFormat::Jsonl,
                Default::default(),
                Budget::default(),
                &mut |c| {
                    if c.value.ct_eq(value.as_bytes()) {
                        found.push(c.occurrence);
                    }
                    true
                },
            )
            .unwrap();
            assert!(report.complete());
            assert_eq!(found.len(), 1);
            let span = &found[0].range;
            assert_eq!(
                &input[span.start as usize..span.end as usize],
                encoded.as_bytes()
            );
        }
    }
}
