//! Gate 11 for vault storage: storing, rotating, reading, looking up,
//! deleting and migrating values never free a block that still holds a
//! fixture.
//!
//! `ProbeMode::Unwiped` turns the allocator's own wipe off, so it checks
//! that the vault code wipes every buffer it fills with a value (the value
//! itself, packed prior values, re-sealed plaintext). The `ProbeMode::Wiping`
//! pass is the gate as written. SQLite's own memory is C `malloc`, which
//! the probe does not see; it only ever holds sealed bytes (gate 2).
//! One test, so no other test's allocations run while the probe is armed.
#![allow(clippy::unwrap_used)]

mod common;

use common::{Fixture, name, secret_item};
use envcloak_core::SecretBytes;
use envcloak_core::vault::{
    Integrity, LockedVault, Migration, MigrationPlan, MigrationTx, VaultError,
};
use envcloak_testkit::{
    Canary, ProbeAllocator, ProbeMode, by_label, canaries, fresh_seed, labels, probe_canaries,
};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

fn value(c: &Canary) -> SecretBytes {
    SecretBytes::copy_from(c.value())
}

fn nothing(_: &MigrationTx<'_>) -> Result<(), VaultError> {
    Ok(())
}

#[test]
fn vault_value_paths_leave_no_fixture_in_freed_memory() {
    let cs = canaries(fresh_seed());

    // Negative control: this binary's probe is armed and sees a plain copy.
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(
        by_label(&cs, labels::GITHUB_TOKEN).value().to_vec(),
    ));
    assert!(session.finish().released_with_needle >= 1);

    // Argon2 runs before the probe is armed; it never sees a fixture.
    let (f, mut v) = Fixture::create();
    for (pass, mode) in [ProbeMode::Unwiped, ProbeMode::Wiping]
        .into_iter()
        .enumerate()
    {
        let session = probe_canaries(&cs, mode);
        let ids = v
            .transact(|t| {
                let mut ids = Vec::new();
                for (n, c) in cs.iter().enumerate() {
                    let item = t.create_item(secret_item(&format!("p{pass}/item-{n}")))?;
                    ids.push(t.add_field(item, name("value"), value(c))?);
                }
                Ok(ids)
            })
            .unwrap();
        // Rotations pack the old value into the prior list, four times so
        // the oldest is dropped.
        for c in cs.iter().take(4) {
            v.transact(|t| t.set_value(ids[0], value(c))).unwrap();
        }
        for (id, c) in ids.iter().zip(&cs).skip(1) {
            assert!(v.read_value(*id).unwrap().ct_eq(c.value()));
        }
        for i in 0..3 {
            drop(v.read_prior(ids[0], i).unwrap());
        }
        assert!(!v.find_by_value(&value(&cs[1])).is_empty());
        let doomed = v
            .find(&envcloak_core::vault::Slug::new(&format!("p{pass}/item-2")).unwrap())
            .unwrap()
            .id;
        v.transact(|t| t.delete_item(doomed)).unwrap();
        // Lock, close, reopen and unlock (metadata only). On the first pass
        // the unlock migrates to version 2, which re-seals every value.
        drop(v.lock());
        let plan = MigrationPlan::new(vec![Migration {
            from: 1,
            ddl: "CREATE TABLE probe_v2 (x INTEGER) STRICT;",
            transform: nothing,
        }])
        .unwrap();
        v = LockedVault::open_with_plan(&f.paths, plan)
            .unwrap()
            .unlock(f.vmk())
            .map_err(|(_, e)| e)
            .unwrap();
        assert_eq!(v.integrity(), Integrity::Ok);
        assert_eq!(v.schema_version(), 2);
        drop(ids);
        let report = session.finish();
        assert!(report.freed > 0, "{mode:?} {report:?}");
        assert_eq!(report.released_with_needle, 0, "{mode:?} {report:?}");
        if mode == ProbeMode::Wiping {
            assert_eq!(report.not_zeroed, 0, "{mode:?} {report:?}");
        }
    }
    drop(v);
}
