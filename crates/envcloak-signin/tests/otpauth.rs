//! R-M2b-05/06/40: independent base32 bytes, hostile enrollment URIs,
//! fixed diagnostics and bounded proptest fuzzing (no fuzz workspace yet).
#![allow(clippy::unwrap_used)]

use envcloak_core::SecretBytes;
use envcloak_signin::otpauth::{self, MAX_LABEL_BYTES, MAX_SEED_BYTES, MAX_URI_BYTES};
use envcloak_signin::totp::{self, Algorithm, Period, TotpParams};
use proptest::prelude::*;
use serde_json::Value;

fn fixtures() -> Vec<Value> {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracles/totp-cases.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn bytes(row: &Value, field: &str) -> Vec<u8> {
    row[field]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect()
}
fn enrollment(base32: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut uri = b"otpauth://totp/Fixture%3A%20account?secret=".to_vec();
    uri.extend_from_slice(base32);
    uri.extend_from_slice(suffix);
    uri
}
fn parse(raw: &[u8]) -> Result<otpauth::TotpSpec, otpauth::OtpauthError> {
    otpauth::parse(&SecretBytes::copy_from(raw))
}
fn refuse(raw: &[u8]) {
    let err = parse(raw).expect_err("hostile input accepted");
    assert_eq!(format!("{err}"), "invalid_otpauth");
    assert_eq!(format!("{err:?}"), "OtpauthError");
}

#[test]
fn accepted_forms_match_python_base32_bytes() {
    for row in fixtures() {
        let base32 = bytes(&row, "base32");
        let expected = bytes(&row, "seed");
        let spec = parse(&enrollment(&base32, b"")).unwrap();
        assert!(
            spec.seed().ct_eq(&expected),
            "base32 case failed: {}",
            row["id"]
        );
        assert!(spec.label().ct_eq(b"Fixture: account"));
        assert!(spec.issuer().is_none());
        assert_eq!(
            spec.params(),
            TotpParams::new(Algorithm::Sha1, 6, 30).unwrap()
        );
        let lower: Vec<u8> = base32.iter().map(u8::to_ascii_lowercase).collect();
        let spec = parse(&enrollment(
            &lower,
            b"&algorithm=SHA512&digits=8&period=45&issuer=F%C3%AAtes",
        ))
        .unwrap();
        assert!(spec.seed().ct_eq(&expected));
        assert!(spec.issuer().unwrap().ct_eq("Fêtes".as_bytes()));
        assert_eq!(
            spec.params(),
            TotpParams::new(Algorithm::Sha512, 8, 45).unwrap()
        );
        let escaped: Vec<u8> = base32
            .iter()
            .flat_map(|b| format!("%{b:02X}").into_bytes())
            .collect();
        let spec = parse(&enrollment(
            &escaped,
            b"&algorithm=SHA256&digits=6&period=4",
        ))
        .unwrap();
        assert!(spec.seed().ct_eq(&expected));
        assert_eq!(spec.params().algorithm(), Algorithm::Sha256);
    }
}

#[test]
fn hostile_grammar_is_refused_without_echo() {
    let rows = fixtures();
    let encoded = bytes(&rows[0], "base32");
    let valid = enrollment(&encoded, b"");
    for suffix in [
        "&algorithm=MD5",
        "&algorithm=sha1",
        "&algorithm=",
        "&digits=7",
        "&digits=06",
        "&period=0",
        "&period=-1",
        "&period=+30",
        "&period=030",
        "&period=18446744073709551616",
        "&period=",
        "&counter=1",
        "&image=x",
        "&unknown=x",
        "&secret=",
        "&secret=x",
        "&algorithm=SHA1&algorithm=SHA512",
        "&digits=6&digits=8",
        "&period=30&period=30",
        "&issuer=x&issuer=y",
        "&issuer=",
        "&issuer=%00",
        "&issuer=%FF",
        "&issuer=%C0%AF",
        "&issuer=%E2%80%AE",
        "&issuer=%",
        "&issuer=%0G",
        "&issuer=x+y",
        "&",
        "&&",
        "&bad",
        "#fragment",
        "&%73ecret=x",
        "&Secret=x",
        "&issuer=a=b",
        "&period=30%00",
    ] {
        refuse(&enrollment(&encoded, suffix.as_bytes()));
    }
    for prefix in [
        "otpauth://hotp/label?secret=",
        "https://totp/label?secret=",
        "otpauth://totp:80/label?secret=",
        "otpauth://user@totp/label?secret=",
        "otpauth://totp/?secret=",
        "otpauth://totp/a/b?secret=",
        "otpauth://totp/%2F?secret=",
        "otpauth://totp/%00?secret=",
        "otpauth://totp/%FF?secret=",
        "otpauth://totp/label?",
        "otpauth://totp/a:b:c?secret=",
        "otpauth://totp/a:%20?secret=",
    ] {
        let mut raw = prefix.as_bytes().to_vec();
        raw.extend_from_slice(&encoded);
        refuse(&raw);
    }
    for raw in [
        b"".as_slice(),
        b"otpauth://totp/label",
        b"\xff",
        b"\0",
        b"otpauth://totp/label?secret=",
    ] {
        refuse(raw);
    }
    for bad in [
        b"0".as_slice(),
        b"1",
        b"8",
        b"!",
        b"%00",
        b"%FF",
        b"A",
        b"ABC",
        b"ABCDEF",
        b"AB",
        b"A=",
        b"AA==",
        b"AA%20",
        b"AA\n",
    ] {
        refuse(&enrollment(bad, b""));
    }
    for byte in [0, b'\n', b'\r', b'\t', b' ', b'\\', 0xff] {
        let mut raw = valid.clone();
        raw.insert(12, byte);
        refuse(&raw);
    }
}

#[test]
fn every_label_component_requires_nonblank_unicode_text() {
    let encoded = bytes(&fixtures()[0], "base32");
    // Check the full label, its prefix/account, and the separate issuer
    // against the same Unicode whitespace rule. Controls stay forbidden.
    for whitespace in [
        ' ', '\u{0085}', '\u{00a0}', '\u{1680}', '\u{2000}', '\u{2007}', '\u{2028}', '\u{2029}',
        '\u{202f}', '\u{205f}', '\u{3000}',
    ] {
        let escaped: String = whitespace
            .to_string()
            .as_bytes()
            .iter()
            .map(|b| format!("%{b:02X}"))
            .collect();
        for label in [
            escaped.clone(),
            format!("{escaped}:account"),
            format!("issuer:{escaped}"),
        ] {
            let mut raw = format!("otpauth://totp/{label}?secret=").into_bytes();
            raw.extend_from_slice(&encoded);
            refuse(&raw);
        }
        refuse(&enrollment(
            &encoded,
            format!("&issuer={escaped}").as_bytes(),
        ));
        if !whitespace.is_control() {
            // Nonblank components keep their original display bytes.
            let mut raw =
                format!("otpauth://totp/{escaped}issuer:{escaped}account?secret=").into_bytes();
            raw.extend_from_slice(&encoded);
            let spec = parse(&raw).unwrap();
            assert!(
                spec.label()
                    .ct_eq(format!("{whitespace}issuer:{whitespace}account").as_bytes())
            );
        }
    }
}

#[test]
fn input_and_decoded_caps_refuse_instead_of_truncating() {
    let raw = vec![b'x'; MAX_URI_BYTES + 1];
    refuse(&raw);
    // All-zero synthetic base32, including canonical tail bits.
    let max = vec![b'A'; (MAX_SEED_BYTES * 8).div_ceil(5)];
    assert_eq!(
        parse(&enrollment(&max, b"")).unwrap().seed().len(),
        MAX_SEED_BYTES
    );
    let large = vec![b'A'; ((MAX_SEED_BYTES + 1) * 8).div_ceil(5)];
    refuse(&enrollment(&large, b""));
    let encoded = bytes(&fixtures()[0], "base32");
    for n in [MAX_LABEL_BYTES, MAX_LABEL_BYTES + 1] {
        let mut raw = b"otpauth://totp/".to_vec();
        raw.extend(vec![b'x'; n]);
        raw.extend_from_slice(b"?secret=");
        raw.extend_from_slice(&encoded);
        assert_eq!(parse(&raw).is_ok(), n == MAX_LABEL_BYTES);
        let mut suffix = b"&issuer=".to_vec();
        suffix.extend(vec![b'x'; n]);
        assert_eq!(
            parse(&enrollment(&encoded, &suffix)).is_ok(),
            n == MAX_LABEL_BYTES
        );
    }
}

#[test]
fn uri_cap_has_valid_boundary_controls() {
    fn escaped(raw: &[u8]) -> String {
        raw.iter().map(|b| format!("%{b:02X}")).collect()
    }
    let seed = vec![b'A'; (MAX_SEED_BYTES * 8).div_ceil(5)];
    // Adjust only the encoding overhead of otherwise valid fields. Both
    // controls satisfy every decoded cap and the enrollment period policy.
    for (label_len, length, accepted) in
        [(256, MAX_URI_BYTES, true), (255, MAX_URI_BYTES + 1, false)]
    {
        let make = |label: String| {
            format!(
                "otpauth://totp/{label}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
                escaped(&seed),
                escaped(&vec![b'y'; MAX_LABEL_BYTES]),
                escaped(b"SHA512"),
                escaped(b"8"),
                escaped(b"300")
            )
        };
        let full_length = make(escaped(&vec![b'x'; label_len])).len();
        assert_eq!((full_length - length) % 2, 0);
        let unescaped = (full_length - length) / 2;
        let label = "x".repeat(unescaped) + &escaped(&vec![b'x'; label_len - unescaped]);
        let raw = make(label);
        assert_eq!(raw.len(), length);
        assert_eq!(parse(raw.as_bytes()).is_ok(), accepted);
    }
}

fn six_digits(raw: &[u8]) -> usize {
    raw.split(|b| !b.is_ascii_digit())
        .filter(|run| run.len() >= 6)
        .count()
}

#[test]
fn public_debug_and_display_are_value_free() {
    let rows = fixtures();
    let mut controls = 0;
    for row in rows {
        let raw = enrollment(&bytes(&row, "base32"), b"");
        let spec = parse(&raw).unwrap();
        let step = row["step"].as_str().unwrap().parse().unwrap();
        let code = totp::code(spec.seed(), spec.params(), step);
        let shown = format!(
            "{spec:?} {spec} {code:?} {code} {:?} {:?} {:?} {} {:?} {}",
            spec.params(),
            spec.params().period(),
            totp::ParamsError,
            totp::ParamsError,
            otpauth::OtpauthError,
            otpauth::OtpauthError
        );
        assert_eq!(six_digits(shown.as_bytes()), 0);
        for secret in [
            bytes(&row, "seed"),
            bytes(&row, "base32"),
            bytes(&row, "expected_code"),
        ] {
            assert!(
                !shown.as_bytes().windows(secret.len()).any(|w| w == secret),
                "public formatting leaked"
            );
        }
        let expected = bytes(&row, "expected_code");
        controls += six_digits(&expected);
    }
    assert!(controls > 1100, "digit sweep positive control failed");
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn parser_fuzz_and_public_debug(raw in prop::collection::vec(any::<u8>(), 0..(MAX_URI_BYTES + 32)), time in any::<u64>(), period in 1..=u64::MAX) {
        let result = parse(&raw);
        let shown = format!("{result:?}");
        prop_assert_eq!(six_digits(shown.as_bytes()), 0);
        if let Ok(spec) = result {
            prop_assert!(!spec.seed().is_empty() && spec.seed().len() <= MAX_SEED_BYTES);
            prop_assert_eq!(six_digits(format!("{spec} {:?}", spec.params()).as_bytes()), 0);
        }
        let p = Period::new(period).unwrap();
        prop_assert_eq!(six_digits(format!("{p:?}").as_bytes()), 0);
        prop_assert_eq!(totp::step_at(time, p), time / period);
        prop_assert_eq!(totp::too_late_in_step(time, p), (u128::from(time / period) + 1) * u128::from(period) - u128::from(time) <= 3);
    }

    #[test]
    fn damaged_valid_enrollment_fuzz(edits in prop::collection::vec((any::<usize>(), any::<u8>()), 0..16)) {
        let encoded = bytes(&fixtures()[0], "base32");
        let mut raw = enrollment(&encoded, b"&algorithm=SHA256&digits=8&period=60&issuer=fixture");
        for (index, byte) in edits { let at = index % raw.len(); raw[at] = byte; }
        let result = parse(&raw);
        prop_assert_eq!(six_digits(format!("{result:?}").as_bytes()), 0);
    }

    #[test]
    fn every_public_debug_type_hides_seed_and_code(index in any::<usize>(), period in 4..=300u64, step in any::<u64>()) {
        let rows = fixtures();
        let row = &rows[index % rows.len()];
        let encoded = bytes(row, "base32");
        let raw = enrollment(&encoded, format!("&period={period}").as_bytes());
        let spec = parse(&raw).unwrap();
        let code = totp::code(spec.seed(), spec.params(), step);
        let shown = format!("{spec:?} {spec} {code:?} {code} {:?} {:?} {:?} {:?} {:?} {:?} {} {:?} {}",
            Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512,
            spec.params(), spec.params().period(), totp::ParamsError, totp::ParamsError,
            otpauth::OtpauthError, otpauth::OtpauthError);
        prop_assert_eq!(six_digits(shown.as_bytes()), 0);
        let seed = bytes(row, "seed");
        for needle in [&seed, &encoded] {
            prop_assert!(!shown.as_bytes().windows(needle.len()).any(|w| w == needle), "seed appeared in public formatting");
        }
    }
}

#[test]
fn enrollment_refuses_periods_without_bounded_eligibility() {
    let encoded = bytes(&fixtures()[0], "base32");
    for period in [0, 1, 2, 3, 4, 30, 300, 301, 3600, u64::MAX] {
        let raw = enrollment(&encoded, format!("&period={period}").as_bytes());
        if (4..=300).contains(&period) {
            assert_eq!(parse(&raw).unwrap().params().period().seconds(), period);
        } else {
            refuse(&raw);
        }
    }
}
