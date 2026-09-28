//! Gate 11 on import's reading and parsing (SPEC §15.2): reading a dotenv
//! file whose lines hold fixture values, in every quoting style, and
//! parsing it, well formed and malformed, never frees a block that still
//! holds a fixture.
//!
//! `ProbeMode::Unwiped` turns the allocator's own wipe off, so it checks
//! that `read_capped` and `parse_dotenv` wipe every buffer they fill with
//! a value (they build them only in `SecretBuf` and `SecretBytes`). One
//! test, so no other test's allocations run while the probe is armed.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use envcloak_core::SecretBytes;
use envcloak_scan::{MAX_DOTENV, open_root, parse_dotenv, read_capped};
use envcloak_testkit::{
    Canary, ProbeAllocator, ProbeMode, by_label, canaries, fresh_seed, labels, probe_canaries,
};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

/// A dotenv file with every canary in every form the parser accepts.
fn dotenv(cs: &[Canary]) -> Vec<u8> {
    let mut f = Vec::new();
    for (i, c) in cs.iter().enumerate() {
        let v = c.as_str();
        let dq = v.replace('\\', "\\\\").replace('"', "\\\"");
        f.extend_from_slice(format!("# entry {i}\nREF_{i}=envcloak://item/n{i}\n").as_bytes());
        if !v.contains([' ', '\t', '#', '"', '\'', '`']) {
            f.extend_from_slice(format!("export UNQUOTED_{i} = {v}  # note\r\n").as_bytes());
        }
        if !v.contains('\'') {
            f.extend_from_slice(format!("SINGLE_{i}='{v}'\n").as_bytes());
        }
        if !v.contains('`') {
            f.extend_from_slice(format!("TICK_{i}=`{v}\n{v}`\n").as_bytes());
        }
        f.extend_from_slice(format!("DOUBLE_{i}=\"\\t{dq}\\n{dq}\r\n\"\n").as_bytes());
        f.extend_from_slice(format!("TEMPLATE_{i}=\"${{X}}{dq}\"\n").as_bytes());
    }
    f
}

/// Malformed files with canaries in them, each failing somewhere.
fn malformed(cs: &[Canary]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for c in cs {
        let v = c.as_str();
        let dq = v.replace('\\', "\\\\").replace('"', "\\\"");
        for f in [
            format!("A=\"{dq}\" trailing {v}\n"),
            format!("A=`{v}"),
            format!("A=\"{dq}\"\nA=\"{dq}\"\n"),
            format!("A=\"{dq}\x00\"\n"),
            format!("A=\"envcloak://Bad/{dq}\"\n"),
        ] {
            out.push(f.into_bytes());
        }
    }
    out
}

#[test]
fn reading_and_parsing_leave_no_fixture_in_freed_memory() {
    let cs = canaries(fresh_seed());

    // Negative control: the probe is armed and sees a plain copy.
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(
        by_label(&cs, labels::OPENAI_API_KEY).value().to_vec(),
    ));
    assert!(session.finish().released_with_needle >= 1);

    // Inputs are built before the probe is armed.
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut body = dotenv(&cs);
    std::fs::write(dir.path().join(".env"), &body).unwrap();
    zeroize::Zeroize::zeroize(&mut body);
    let bad: Vec<SecretBytes> = malformed(&cs)
        .into_iter()
        .map(SecretBytes::from_vec)
        .collect();
    let root = open_root(dir.path()).unwrap();

    for mode in [ProbeMode::Unwiped, ProbeMode::Wiping] {
        let session = probe_canaries(&cs, mode);
        let (bytes, _) = read_capped(&root, Path::new(".env"), MAX_DOTENV).unwrap();
        let entries = parse_dotenv(&bytes).unwrap();
        assert!(entries.len() >= 4 * cs.len());
        drop(entries);
        drop(bytes);
        for b in &bad {
            assert!(parse_dotenv(b).is_err());
        }
        let report = session.finish();
        assert!(report.freed > 0, "{mode:?} {report:?}");
        assert_eq!(report.released_with_needle, 0, "{mode:?} {report:?}");
        if mode == ProbeMode::Wiping {
            assert_eq!(report.not_zeroed, 0, "{mode:?} {report:?}");
        }
    }
}
