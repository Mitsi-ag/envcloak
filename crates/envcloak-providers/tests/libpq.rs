//! Passwords in libpq's keyword form, counted against libpq itself (review
//! F-65, SPEC §6.4). libpq decodes a backslash before any byte in a value,
//! quoted or not, so a 15-character password written with one escaped
//! backslash is 16 bytes: counted as bytes, it passed for 16 characters,
//! and an agent could confirm guesses of it.
//!
//! The connection strings and libpq's counts come from libpq's own parser
//! (`tests/fixtures/libpq/generate.py`, which calls `PQconninfoParse` and
//! keeps a line only when libpq gives back the password written), loaded as
//! bytes. On a failure the line number is printed, never the string.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use envcloak_core::SecretBytes;
use envcloak_providers::password_chars;

/// Each line of the fixture: libpq's count, whether EnvCloak's is exactly
/// that or may be less, and the connection string.
fn cases() -> Vec<(usize, usize, bool, Vec<u8>)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/libpq/passwords.txt");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(' ');
        let (chars, kind, written) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        assert!(parts.next().is_none(), "line {}", n + 1);
        // Every byte but printable ASCII other than `%` is written `%XX`.
        let w = written.as_bytes();
        let mut bytes = Vec::with_capacity(w.len());
        let mut i = 0;
        while i < w.len() {
            if w[i] == b'%' {
                let hex = std::str::from_utf8(&w[i + 1..i + 3]).unwrap();
                bytes.push(u8::from_str_radix(hex, 16).unwrap());
                i += 3;
            } else {
                bytes.push(w[i]);
                i += 1;
            }
        }
        let exact = match kind {
            "exact" => true,
            "at-most" => false,
            _ => panic!("line {}: {kind}", n + 1),
        };
        out.push((n + 1, chars.parse().unwrap(), exact, bytes));
    }
    out
}

/// Every password counts no more characters than libpq decodes it to, and
/// exactly as many where the reading holds it whole: unquoted with its
/// backslashes, quotes and whitespace escaped, quoted, with every byte
/// escaped, and with each kind of whitespace libpq takes around `=`. So a
/// password under 16 characters counts as short however it is escaped,
/// and 16 characters (the controls) still count 16.
#[test]
fn libpq_passwords_count_no_more_than_libpq_decodes() {
    let cases = cases();
    assert!(cases.len() >= 500, "{}", cases.len());
    let (mut exact, mut short, mut controls) = (0, 0, 0);
    for (line, libpq, is_exact, bytes) in &cases {
        let got = password_chars(&SecretBytes::copy_from(bytes));
        let Some(got) = got else {
            panic!("line {line}: no password read");
        };
        assert!(
            got <= *libpq,
            "line {line}: {got} characters, libpq {libpq}"
        );
        if *is_exact {
            assert_eq!(got, *libpq, "line {line}");
            exact += 1;
            controls += usize::from(*libpq >= 16);
        }
        short += usize::from(*libpq < 16);
    }
    // The fixture exercises both sides of the threshold, exactly.
    assert!(exact >= 200 && short >= 300 && controls >= 50);
}
