//! b15 primitive slice, R-M2b-05/06/40/52. The bytes come from the
//! independent Cycle206 Python/Node oracle, anchored to RFC 6238.
#![allow(clippy::unwrap_used)]

use envcloak_core::SecretBytes;
use envcloak_signin::totp::{
    Algorithm, Period, TotpParams, code, refused_after_start, seconds_left, step_at,
    too_late_in_step,
};
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

#[test]
fn rfc_and_independent_oracle_bytes() {
    let rows = fixtures();
    assert!(rows.len() > 1100);
    let mut offsets = [[false; 16]; 3];
    let mut rfc = 0;
    let mut leading_zeroes = 0;
    for row in rows {
        let (algorithm, index) = match row["algorithm"].as_str().unwrap() {
            "sha1" => (Algorithm::Sha1, 0),
            "sha256" => (Algorithm::Sha256, 1),
            "sha512" => (Algorithm::Sha512, 2),
            _ => panic!("invalid fixture algorithm"),
        };
        let seed = SecretBytes::from_vec(bytes(&row, "seed"));
        let params = TotpParams::new(algorithm, row["digits"].as_u64().unwrap() as u8, 30).unwrap();
        let step = row["step"].as_str().unwrap().parse().unwrap();
        let actual = code(&seed, params, step);
        let expected = bytes(&row, "expected_code");
        assert!(
            actual.as_secret().ct_eq(&expected),
            "TOTP case failed: {}",
            row["id"]
        );
        let mut wrong = expected.clone();
        wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
        assert!(
            !actual.as_secret().ct_eq(&wrong),
            "comparison control failed"
        );
        offsets[index][row["offset"].as_u64().unwrap() as usize] = true;
        rfc += usize::from(row["id"].as_str().unwrap().starts_with("rfc6238-"));
        leading_zeroes += usize::from(expected[0] == b'0');
        if row["kind"] == "time" {
            let time: u64 = row["time"].as_str().unwrap().parse().unwrap();
            let epoch: u64 = row["t0"].as_str().unwrap().parse().unwrap();
            let period = Period::new(row["period"].as_u64().unwrap()).unwrap();
            assert_eq!(step_at(time - epoch, period), step);
        }
    }
    assert_eq!(rfc, 36);
    assert!(leading_zeroes > 0);
    assert!(offsets.iter().flatten().all(|covered| *covered));
}

#[test]
fn step_boundaries_and_last_three_seconds() {
    for period in [1, 2, 3, 4, 15, 30, 45, 60, 86400, u64::MAX] {
        let p = Period::new(period).unwrap();
        for time in [
            0,
            1,
            period.saturating_sub(4),
            period.saturating_sub(3),
            period - 1,
            period,
            period.saturating_add(1),
            u64::MAX,
        ] {
            // u128 arithmetic is independent of the implementation's u64
            // remainder/subtraction and remains defined at u64::MAX.
            let start = u128::from(time) / u128::from(period) * u128::from(period);
            let remaining = start + u128::from(period) - u128::from(time);
            assert_eq!(step_at(time, p), (start / u128::from(period)) as u64);
            assert_eq!(seconds_left(time, p), remaining as u64);
            assert_eq!(too_late_in_step(time, p), remaining <= 3);
        }
    }
}

#[test]
fn after_start_refuses_current_and_previous_without_underflow() {
    let p = Period::new(30).unwrap();
    for (now, expected) in [
        (0, [0, 0]),
        (29, [0, 0]),
        (30, [1, 0]),
        (59, [1, 0]),
        (60, [2, 1]),
        (61, [2, 1]),
    ] {
        assert_eq!(refused_after_start(now, p), expected);
    }
    let p = Period::new(1).unwrap();
    assert_eq!(refused_after_start(u64::MAX, p), [u64::MAX, u64::MAX - 1]);
}

#[test]
fn invalid_parameters_cannot_reach_arithmetic() {
    assert!(Period::new(0).is_err());
    for digits in 0..=u8::MAX {
        assert_eq!(
            TotpParams::new(Algorithm::Sha1, digits, 30).is_ok(),
            matches!(digits, 6 | 8)
        );
    }
    assert!(TotpParams::new(Algorithm::Sha512, 8, 0).is_err());
}
