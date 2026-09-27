//! Gate 11's allocator probe on detection: matching fixture values against
//! the registry's patterns frees no block that holds one.
//!
//! `ProbeMode::Unwiped` turns the allocator's own wipe off, so this checks
//! more than the gate asks: detection never copies a value into the heap
//! at all. The patterns keep no captures and the matcher's caches hold
//! automaton states, not input; a detection holds provider ids only. One
//! test, so no other test's allocations run while the probe is armed.
#![allow(clippy::unwrap_used)]

use envcloak_core::SecretBytes;
use envcloak_providers::load_embedded;
use envcloak_testkit::{
    ProbeAllocator, ProbeMode, by_label, canaries, fresh_seed, labels, probe_canaries,
};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

#[test]
fn detection_leaves_no_fixture_in_freed_memory() {
    let cs = canaries(fresh_seed());
    let registry = load_embedded().unwrap();
    let values: Vec<SecretBytes> = cs
        .iter()
        .map(|c| SecretBytes::copy_from(c.value()))
        .collect();
    // The matcher builds its caches on first use; build them before the
    // probe is armed, as a long-running importer would have.
    for v in &values {
        drop(registry.detect(v, None));
    }

    // Negative control: this binary's probe is armed and sees a plain copy.
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(
        by_label(&cs, labels::OPENAI_API_KEY).value().to_vec(),
    ));
    assert!(session.finish().released_with_needle >= 1);

    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    let mut found = 0;
    for (v, c) in values.iter().zip(&cs) {
        for env in [None, Some(c.label.as_str()), Some("DEEPSEEK_API_KEY")] {
            let d = std::hint::black_box(registry.detect(v, env));
            found += usize::from(d.provider.is_some());
        }
    }
    let report = session.finish();
    // The OpenAI, rotated OpenAI, Stripe and GitHub fixtures, three times.
    assert_eq!(found, 12);
    assert!(report.freed > 0, "{report:?}");
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}
