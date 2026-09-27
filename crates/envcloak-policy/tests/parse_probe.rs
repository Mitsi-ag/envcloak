//! Gate 11 on the parsing paths: parsing an env file whose ordinary lines
//! hold fixture values, in every quoting style and in malformed lines, never
//! frees a block that still holds one; nor does parsing a manifest that has
//! a fixture pasted into it.
//!
//! `ProbeMode::Unwiped` turns the allocator's own wipe off, so it checks
//! that the env-file parser wipes every buffer it fills with a value (it
//! builds them only in `SecretBuf` and `SecretBytes`). The manifest parser
//! is a TOML library that does not wipe: a manifest holds no values by
//! design, and one pasted in by mistake is covered by the wiping allocator
//! the binaries install, which the `ProbeMode::Wiping` pass checks. One
//! test, so no other test's allocations run while the probe is armed.
#![allow(clippy::unwrap_used)]

use envcloak_core::SecretBytes;
use envcloak_policy::{EnvFileRefs, parse_env_file_refs, parse_manifest};
use envcloak_testkit::{
    Canary, ProbeAllocator, ProbeMode, ProbeReport, by_label, canaries, fresh_seed, labels,
    probe_canaries,
};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

fn assert_clean(report: &ProbeReport, mode: ProbeMode, what: &str) {
    assert!(report.freed > 0, "{what} {mode:?} {report:?}");
    assert_eq!(report.released_with_needle, 0, "{what} {mode:?} {report:?}");
    if mode == ProbeMode::Wiping {
        assert_eq!(report.not_zeroed, 0, "{what} {mode:?} {report:?}");
    }
}

/// An env file with every canary in every form the parser accepts, and
/// some references between them.
fn env_file(cs: &[Canary]) -> Vec<u8> {
    let mut f = Vec::new();
    for (i, c) in cs.iter().enumerate() {
        let v = c.as_str();
        let dq = v.replace('\\', "\\\\").replace('"', "\\\"");
        f.extend_from_slice(format!("# entry {i}\n").as_bytes());
        f.extend_from_slice(format!("REF_{i}=envcloak://item/n{i}#api_key\n").as_bytes());
        if !v.contains([' ', '\t', '#', '"', '\'']) {
            f.extend_from_slice(format!("UNQUOTED_{i}={v}\n").as_bytes());
            f.extend_from_slice(format!("export COMMENTED_{i} = {v}  # note\r\n").as_bytes());
        }
        if !v.contains('\'') {
            f.extend_from_slice(format!("SINGLE_{i}='{v}'\n").as_bytes());
        }
        f.extend_from_slice(format!("DOUBLE_{i}=\"{dq}\"\n").as_bytes());
        f.extend_from_slice(format!("ESCAPED_{i}=\"\\t{dq}\\n{dq}\\\\\"\n").as_bytes());
        f.extend_from_slice(format!("MULTI_{i}=\"{dq}\r\n{dq}\n\"\n").as_bytes());
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
            format!("A=\"{dq}\n"),
            format!("A='{v}"),
            format!("A=\"{dq}\"\nB=2\nA=\"{dq}\"\n"),
            format!("A=\"{dq}\x00\"\n"),
            format!("A=\"{dq}\"\nB\n"),
            format!("A=\"envcloak://Bad/{dq}\"\n"),
        ] {
            out.push(f.into_bytes());
        }
    }
    out
}

/// Parses everything once. Returns the parsed file so the caller drops it
/// while the probe is still armed.
fn parse_all(file: &SecretBytes, bad: &[SecretBytes], manifests: &[Vec<u8>]) -> EnvFileRefs {
    let parsed = parse_env_file_refs(file).unwrap();
    for b in bad {
        assert!(parse_env_file_refs(b).is_err());
    }
    for m in manifests {
        let _ = parse_manifest(m);
    }
    parsed
}

#[test]
fn parsing_leaves_no_fixture_in_freed_memory() {
    let cs = canaries(fresh_seed());

    // Negative control: this binary's probe is armed and sees a plain copy.
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(
        by_label(&cs, labels::OPENAI_API_KEY).value().to_vec(),
    ));
    assert!(session.finish().released_with_needle >= 1);

    // Inputs are built before the probe is armed and dropped (wiped) after.
    let file = SecretBytes::from_vec(env_file(&cs));
    let bad: Vec<SecretBytes> = malformed(&cs)
        .into_iter()
        .map(SecretBytes::from_vec)
        .collect();
    let v = by_label(&cs, labels::GITHUB_TOKEN).as_str();
    let manifests: Vec<Vec<u8>> = [
        format!("[env]\nGITHUB_TOKEN = \"{v}\"\n"),
        format!("[env]\nGITHUB_TOKEN = {{ ref = \"{v}\" }}\n"),
        format!("# {v}\n[env]\nA = \"a/b\"\n"),
        format!("[env]\nA = {v}\n"),
    ]
    .map(String::into_bytes)
    .into();

    // The env-file parser wipes its own buffers.
    let mode = ProbeMode::Unwiped;
    let session = probe_canaries(&cs, mode);
    let parsed = parse_env_file_refs(&file).unwrap();
    assert!(parsed.plain.len() >= 4 * cs.len());
    assert_eq!(parsed.refs.len(), cs.len());
    drop(parsed);
    for b in &bad {
        assert!(parse_env_file_refs(b).is_err());
    }
    assert_clean(&session.finish(), mode, "env-file parsing");

    // The gate as written: with the wiping allocator, nothing freed while
    // parsing env files or manifests holds a fixture.
    let mode = ProbeMode::Wiping;
    let session = probe_canaries(&cs, mode);
    let parsed = parse_all(&file, &bad, &manifests);
    drop(parsed);
    let report = session.finish();
    assert_clean(&report, mode, "env-file and manifest parsing");
    // The manifests' copies were seen and wiped, so the probe was looking.
    assert!(report.held_needle > 0, "{report:?}");
}
