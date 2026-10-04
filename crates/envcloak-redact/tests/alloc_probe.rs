//! Regression probe for memory hygiene (gate 11): no buffer holding secret
//! bytes may be released without being wiped. This binary installs the
//! shared inspection allocator from `envcloak-sys` (through the testkit),
//! which zero-initializes every block, forces every reallocation to move and
//! inspects each block just before it is freed.
#![allow(clippy::unwrap_used)]

use envcloak_redact::RedactorBuilder;
use envcloak_testkit::{
    ProbeAllocator, ProbeMode, by_label, canaries, fresh_seed, labels, probe_canaries,
};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

#[test]
fn probe_detects_an_unwiped_growing_buffer() {
    let cs = canaries(fresh_seed());
    let needle = by_label(&cs, labels::OPENAI_API_KEY).value();
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    let mut v = Vec::with_capacity(needle.len());
    v.extend_from_slice(needle);
    v.extend_from_slice(b"forces a moving reallocation");
    drop(std::hint::black_box(v));
    let report = session.finish();
    assert!(
        report.released_with_needle >= 1,
        "the probe must catch the bug it guards against"
    );
}

#[test]
fn stream_redactor_frees_no_unwiped_secret_bytes() {
    let cs = canaries(fresh_seed());
    let needle = by_label(&cs, labels::OPENAI_API_KEY).value();
    let (redactor, _) = RedactorBuilder::new().secret("probe", needle).build();
    let mut text = b"prefix noise ".to_vec();
    text.extend_from_slice(needle);
    text.extend_from_slice(b" suffix noise");
    let splits: Vec<(Vec<u8>, Vec<u8>)> = (0..=text.len())
        .map(|i| (text[..i].to_vec(), text[i..].to_vec()))
        .collect();
    let mut outputs: Vec<Vec<u8>> = Vec::with_capacity(splits.len());

    // The allocator does not wipe here, so the stream code must.
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    for (a, b) in &splits {
        let mut out = Vec::new();
        let mut s = redactor.stream();
        s.push(a, &mut out);
        s.flush_idle(&mut out);
        s.push(b, &mut out);
        s.finish(&mut out);
        outputs.push(out);
    }
    let report = session.finish();

    assert_eq!(
        report.released_with_needle, 0,
        "a buffer holding secret bytes was freed unwiped"
    );
    for out in &outputs {
        assert!(!out.windows(needle.len()).any(|w| w == needle));
    }
}

#[test]
fn building_and_dropping_the_redactor_leaves_nothing_under_the_wiping_allocator() {
    // The automata keep their own unwiped copies of the patterns; the wiping
    // allocator is what clears them (the runner, envcloak-exec, relies on
    // this).
    let cs = canaries(fresh_seed());
    let needle = by_label(&cs, labels::OPENAI_API_KEY).value();
    let session = probe_canaries(&cs, ProbeMode::Wiping);
    let (redactor, _) = RedactorBuilder::new().secret("probe", needle).build();
    let mut out = Vec::new();
    let mut s = redactor.stream();
    s.push(needle, &mut out);
    s.finish(&mut out);
    drop(s);
    drop(redactor);
    let report = session.finish();
    assert!(
        report.held_needle >= 1,
        "the automata must have held the needle: {report:?}"
    );
    assert_eq!(report.not_zeroed, 0, "{report:?}");
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}

/// The CR LF forms PTY mode adds (D-19) are built and freed like the other
/// variants: nothing holding the value is released unwiped.
#[test]
fn building_with_cr_lf_variants_leaves_nothing_under_the_wiping_allocator() {
    let cs = canaries(fresh_seed());
    let needle = by_label(&cs, labels::OPENAI_API_KEY).value();
    let mut value = needle.to_vec();
    value.extend_from_slice(b"\nsecond line\n");
    let mut shown = needle.to_vec();
    shown.extend_from_slice(b"\r\nsecond line\r\n");
    let session = probe_canaries(&cs, ProbeMode::Wiping);
    let (redactor, _) = RedactorBuilder::new()
        .crlf_variants(true)
        .secret("probe", &value)
        .build();
    let mut out = Vec::new();
    let mut s = redactor.stream();
    s.push(&shown, &mut out);
    s.finish(&mut out);
    drop(s);
    drop(redactor);
    let report = session.finish();
    assert_eq!(out, b"[envcloak:probe]");
    assert!(report.held_needle >= 1, "{report:?}");
    assert_eq!(report.not_zeroed, 0, "{report:?}");
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}
