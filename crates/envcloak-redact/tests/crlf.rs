//! The CR LF form of a value holding LF (M2 plan D-19): in PTY mode the
//! command's output passes through the slave's line discipline, which
//! writes every LF as CR LF (`ONLCR`), so a multi-line value such as a PEM
//! block reaches the redactor in that form. With
//! `RedactorBuilder::crlf_variants(true)` it is redacted whole, also when
//! it arrives split at any byte; without it, it passes through (the
//! positive control: the variant is what catches it). The form a real
//! terminal writes is checked against this one in
//! `crates/envcloak-exec/tests/pty_spawn.rs`.
#![allow(clippy::unwrap_used)]

use base64::Engine as _;
use envcloak_redact::{Redactor, RedactorBuilder};
use envcloak_testkit::fresh_seed;

const LABEL: &str = "tls/key";
const MARKER: &str = "[envcloak:tls/key]";

/// A PEM-shaped block made at run time: a header and footer split so no
/// key-shaped literal is in the source, and a base64 body of random bytes
/// in 64-character lines, each ended by LF.
fn pem(seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut bytes = Vec::with_capacity(192);
    for _ in 0..192 {
        // SplitMix64, one byte per step.
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        bytes.push(u8::try_from((z ^ (z >> 31)) & 0xff).unwrap());
    }
    let body = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let kind = concat!("ENVCLOAK ", "TEST ", "BLOCK");
    let mut pem = format!("-----{} {kind}-----\n", "BEGIN").into_bytes();
    for line in body.as_bytes().chunks(64) {
        pem.extend_from_slice(line);
        pem.push(b'\n');
    }
    pem.extend_from_slice(format!("-----{} {kind}-----\n", "END").as_bytes());
    pem
}

/// Every LF preceded by a CR, as `ONLCR` writes it.
fn as_a_terminal_writes_it(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in value {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

fn redactor(value: &[u8], crlf: bool) -> Redactor {
    RedactorBuilder::new()
        .crlf_variants(crlf)
        .secret(LABEL, value)
        .build()
        .0
}

fn streamed(r: &Redactor, input: &[u8], split: usize) -> Vec<u8> {
    let mut s = r.stream();
    let mut out = Vec::new();
    s.push(&input[..split], &mut out);
    s.push(&input[split..], &mut out);
    s.finish(&mut out);
    out
}

fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn a_pem_block_in_its_cr_lf_form_is_redacted_whole() {
    let seed = fresh_seed();
    let value = pem(seed);
    let shown = as_a_terminal_writes_it(&value);
    assert_ne!(shown, value);
    let r = redactor(&value, true);
    let mut output = b"key follows\r\n".to_vec();
    output.extend_from_slice(&shown);
    output.extend_from_slice(b"done\r\n");
    let expected = format!("key follows\r\n{MARKER}done\r\n").into_bytes();
    assert_eq!(r.redact(&output), expected, "seed {seed}");
    // Split at every byte: a value arriving in two reads is still caught.
    for split in 0..=output.len() {
        assert_eq!(
            streamed(&r, &output, split),
            expected,
            "seed {seed}, split {split}"
        );
    }
    // The raw form stays covered.
    assert_eq!(r.redact(&value), MARKER.as_bytes(), "seed {seed}");
    // A body line on its own is no match, and nothing of the block remains
    // after redaction.
    let body_line = value.split(|b| *b == b'\n').nth(1).unwrap();
    assert!(!holds(&r.redact(&output), body_line), "seed {seed}");
}

/// The positive control: without the variant the CR LF form passes
/// through, body lines and all.
#[test]
fn without_the_variant_the_cr_lf_form_passes_through() {
    let seed = fresh_seed();
    let value = pem(seed);
    let shown = as_a_terminal_writes_it(&value);
    let r = redactor(&value, false);
    assert_eq!(r.redact(&value), MARKER.as_bytes(), "seed {seed}");
    assert_eq!(r.redact(&shown), shown, "seed {seed}");
}

/// A CR already before an LF gets another, as `ONLCR` gives it; a value
/// without LF has no other form.
#[test]
fn every_lf_gets_its_cr_and_a_value_without_lf_has_no_other_form() {
    let seed = fresh_seed();
    let mut value = pem(seed);
    let at = value.iter().position(|b| *b == b'\n').unwrap();
    value.insert(at, b'\r');
    let shown = as_a_terminal_writes_it(&value);
    assert!(holds(&shown, b"\r\r\n"));
    let r = redactor(&value, true);
    assert_eq!(r.redact(&shown), MARKER.as_bytes(), "seed {seed}");
    let flat: Vec<u8> = value.iter().copied().filter(|b| *b != b'\n').collect();
    let r = redactor(&flat, true);
    assert_eq!(r.redact(&flat), MARKER.as_bytes());
}
