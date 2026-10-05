//! Gate 11 for the runner (SPEC §15.2): building the child's environment,
//! and building and dropping the run's redactor, leave no freed block
//! holding a value. `Command::env` and the spawn copy the values into
//! blocks the runner cannot wipe itself, and the redactor's automata keep
//! unwiped copies of its patterns; the wiping allocator the binaries
//! install is what clears them. This binary installs the inspection
//! allocator in its wiping mode, which records every block that held a
//! canary and checks that each was all zeros after the wipe.
#![allow(clippy::unwrap_used)]

use std::os::fd::OwnedFd;
use std::time::Duration;

use envcloak_core::SecretBytes;
use envcloak_core::vault::Slug;
use envcloak_exec::{ChildExit, Label, RunSpec, ShortPolicy, build_redactor, run};
use envcloak_policy::EnvName;
use envcloak_testkit::{
    ProbeAllocator, ProbeMode, by_label, canaries, fresh_seed, labels, probe_canaries,
};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

/// The probe is process-wide: the tests take turns.
static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn dev_null() -> OwnedFd {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap()
        .into()
}

#[test]
fn starting_a_child_with_values_frees_nothing_unwiped() {
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    let cs = canaries(fresh_seed());
    let labels_ = [
        labels::OPENAI_API_KEY,
        labels::STRIPE_SECRET_KEY,
        labels::DATABASE_URL,
    ];
    let session = probe_canaries(&cs, ProbeMode::Wiping);
    {
        let slugs: Vec<Slug> = labels_
            .iter()
            .map(|l| Slug::new(&format!("{}/t", l.to_ascii_lowercase())).unwrap())
            .collect();
        let values: Vec<SecretBytes> = labels_
            .iter()
            .map(|l| SecretBytes::copy_from(by_label(&cs, l).value()))
            .collect();
        let (redactor, _) = {
            let labels: Vec<Label<'_>> = slugs
                .iter()
                .zip(&values)
                .map(|(slug, value)| Label {
                    slug,
                    value,
                    short: ShortPolicy::Refuse,
                })
                .collect();
            build_redactor(&labels).unwrap()
        };
        let injected = labels_
            .iter()
            .zip(values)
            .map(|(l, v)| (EnvName::new(l).unwrap(), v))
            .collect();
        let mut spec = RunSpec::new(
            vec!["/bin/sh".into(), "-c".into(), "exit 0".into()],
            injected,
            redactor,
            dev_null(),
            dev_null(),
        );
        spec.idle_flush = Duration::from_millis(40);
        let exit = run(spec).unwrap();
        assert_eq!(exit, ChildExit::Code(0));
    }
    let report = session.finish();
    // The environment and the automata held the values ...
    assert!(report.held_needle >= 3, "{report:?}");
    // ... and every block was wiped before it went back.
    assert_eq!(report.not_zeroed, 0, "{report:?}");
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}
