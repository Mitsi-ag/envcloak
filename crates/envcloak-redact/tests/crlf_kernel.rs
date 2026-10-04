//! The CR LF variants against what a real terminal writes (M2 plan D-19;
//! the oracle is adopted from an independent review, cycle 356).
//!
//! `crlf_kernel/kernel-worker.py` writes eight shapes of value holding LF
//! (and one without) to fresh pseudo-terminals with `OPOST|ONLCR` set and
//! with no output processing, and returns what the master sides showed:
//! the kernel's own "cooked" form, not one written by hand. Each cooked
//! form must be redacted whole by a redactor built with
//! `crlf_variants(true)`, also streamed: split in two at every byte, with
//! and without an idle flush at the split, and byte by byte with and
//! without a flush after each byte. The controls: the raw capture equals
//! the value and is redacted; ordinary output is left alone; without the
//! variant, a cooked form that changed is passed through unchanged (six of
//! the shapes), except the leading-LF shape, whose cooked form still holds
//! the whole raw value after the inserted CR (so raw matching redacts it
//! anyway: one), and the shape without LF is the same both ways and
//! redacted. Drop the variant and the first assertion fails.

use std::process::{Command, Stdio};

use envcloak_redact::RedactorBuilder;
use serde_json::Value;

/// `assert_eq!` without the two sides in the message: they may hold a
/// fixture value, and failures name a canary by its label or seed only
/// (as `envcloak_testkit::Canary`'s `Debug` does), never by its bytes.
macro_rules! assert_same {
    ($a:expr, $b:expr $(,)?) => {
        assert!($a == $b, "the two sides differ (not printed: they may hold a value)")
    };
    ($a:expr, $b:expr, $($msg:tt)+) => {
        assert!($a == $b, $($msg)+)
    };
}

fn bytes(v: &Value) -> Vec<u8> {
    v.as_array()
        .expect("an array of bytes")
        .iter()
        .map(|x| u8::try_from(x.as_u64().expect("a byte")).expect("a byte"))
        .collect()
}

fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn every_cr_lf_form_a_real_terminal_writes_is_redacted() {
    let worker = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("crlf_kernel")
        .join("kernel-worker.py");
    let out = Command::new(envcloak_testkit::lifeline::python3())
        .args(["-I", "-S"])
        .arg(&worker)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .expect("python3 runs");
    assert!(
        out.status.success(),
        "the kernel worker failed: {:?}",
        out.status
    );
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout).expect("rows");
    assert_eq!(rows.len(), 8, "the shapes");
    let marker: &[u8] = b"[envcloak:kernel]";
    let benign: &[u8] = b"ordinary output without a fixture marker";
    let (mut cuts, mut idle_cuts, mut streams) = (0usize, 0usize, 0usize);
    let (mut disabled_sensitive, mut existing_raw, mut unchanged) = (0usize, 0usize, 0usize);
    for (shape, row) in rows.iter().enumerate() {
        let value = bytes(&row["value"]);
        let cooked = bytes(&row["cooked"]);
        let raw = bytes(&row["raw"]);
        assert_same!(raw, value, "shape {shape}: the raw capture is the value");
        let (r, _) = RedactorBuilder::new()
            .crlf_variants(true)
            .secret("kernel", &value)
            .build();
        assert_same!(
            r.redact(&cooked),
            marker,
            "shape {shape}: the terminal's form"
        );
        assert_same!(r.redact(&raw), marker, "shape {shape}: the raw form");
        assert!(
            r.find_labels(&cooked).contains(&"kernel"),
            "shape {shape}: owner"
        );
        for at in 0..=cooked.len() {
            for idle in [false, true] {
                let mut stream = r.stream();
                let mut got = Vec::new();
                stream.push(&cooked[..at], &mut got);
                if idle {
                    stream.flush_idle(&mut got);
                }
                stream.push(&cooked[at..], &mut got);
                stream.finish(&mut got);
                assert_same!(got, marker, "shape {shape}: split at {at}, idle {idle}");
                if idle {
                    idle_cuts += 1;
                } else {
                    cuts += 1;
                }
            }
        }
        for idle in [false, true] {
            let mut stream = r.stream();
            let mut got = Vec::new();
            for b in cooked.chunks(1) {
                stream.push(b, &mut got);
                if idle {
                    stream.flush_idle(&mut got);
                }
            }
            stream.finish(&mut got);
            assert_same!(got, marker, "shape {shape}: byte by byte, idle {idle}");
            streams += 1;
        }
        let (off, _) = RedactorBuilder::new()
            .crlf_variants(false)
            .secret("kernel", &value)
            .build();
        if cooked == value {
            assert_same!(off.redact(&cooked), marker, "shape {shape}: no LF");
            unchanged += 1;
        } else if holds(&cooked, &value) {
            assert!(
                !holds(&off.redact(&cooked), &value),
                "shape {shape}: the raw value inside"
            );
            existing_raw += 1;
        } else {
            assert_same!(
                off.redact(&cooked),
                cooked,
                "shape {shape}: without the variant the terminal's form passes"
            );
            disabled_sensitive += 1;
        }
        assert_same!(r.redact(benign), benign, "shape {shape}: benign output");
    }
    assert_eq!(
        (disabled_sensitive, existing_raw, unchanged),
        (6, 1, 1),
        "the controls"
    );
    println!(
        "crlf_kernel: 8 shapes, {cuts} splits, {idle_cuts} idle splits, {streams} byte \
         streams; controls: {disabled_sensitive} need the variant, {existing_raw} holds the raw \
         value, {unchanged} has no LF"
    );
}
