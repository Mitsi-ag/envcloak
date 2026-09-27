//! `kill -9` during a restore leaves the old vault or the new one, never
//! neither (M1 plan, T4), and a restored vault's digest verifies.
//!
//! The restorer is this test binary, re-run as a child. It restores a
//! backup over a vault that has moved on since, printing each step it
//! passes. The parent kills it after a chosen step, at a random moment
//! within that step's measured duration (or at a random moment of the
//! whole run), then opens the vault. It must open; its digest must verify;
//! and it must hold exactly the old vault's items and passphrase envelope,
//! or exactly the backup's items with the new passphrase envelope and the
//! kit confirmed. Up to the step that keeps the old vault aside it must be
//! the old one, and from the step after the rename the new one. A few
//! rounds restore where no vault exists: then there is no vault or the new
//! one. Set `ENVCLOAK_RESTORE_CRASH_SEED` to replay a run.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::BufReader;
use std::time::{Duration, Instant};

use common::{
    KitFixture, Rng, dir_names, kill_child, last_number, name, other_passphrase, read_stdin, rest,
    secret_item, spawn_self, wait_for,
};
use envcloak_core::backup::{RestoreStep, restore_backup_observed};
use envcloak_core::crypto::{KdfParams, UnlockerKind};
use envcloak_core::vault::{Integrity, ItemMeta, LockedVault, VaultErrorKind, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes};
use envcloak_testkit::fresh_seed;

const RESTORER: &str = "ENVCLOAK_RESTORE_CRASH_DATA";
const BACKUP: &str = "ENVCLOAK_RESTORE_CRASH_BACKUP";
const SEED: &str = "ENVCLOAK_RESTORE_CRASH_SEED";
/// Steps 1 to 7, in the order a restore passes them.
const STEPS: u64 = 7;
const ROUNDS_PER_TARGET: u64 = 5;
/// The step after which `vault.db` is renamed over: from the next one on,
/// the new vault is in place.
const KEPT: u64 = 6;
const INSTALLED: u64 = 7;

fn step_number(s: RestoreStep) -> u64 {
    match s {
        RestoreStep::KitAccepted => 1,
        RestoreStep::OldVaultOpened => 2,
        RestoreStep::StagingWritten => 3,
        RestoreStep::StagingReady => 4,
        RestoreStep::OldVaultClosed => 5,
        RestoreStep::OldVaultKept => KEPT,
        RestoreStep::Installed => INSTALLED,
        _ => 0,
    }
}

/// Runs only as the child the test below starts. Reads the kit's text and
/// the new passphrase from stdin, one per line.
#[test]
fn restore_child() {
    let Some(data) = std::env::var_os(RESTORER) else {
        return;
    };
    let backup = std::env::var_os(BACKUP).unwrap();
    let input = read_stdin();
    let at = input.iter().position(|b| *b == b'\n').unwrap();
    let kit = RecoveryKit::parse(&SecretBytes::copy_from(&input[..at])).unwrap();
    let pass = SecretBytes::copy_from(&input[at + 1..]);
    println!("@@step 0");
    let (v, _) = restore_backup_observed(
        &VaultPaths::under(data),
        std::path::Path::new(&backup),
        &kit,
        &pass,
        &KdfParams::minimum(),
        &mut |s| println!("@@step {}", step_number(s)),
    )
    .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    println!("@@done");
    std::thread::sleep(Duration::from_secs(60));
}

fn seed() -> u64 {
    std::env::var(SEED)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(fresh_seed)
}

/// Replaces the vault directory's contents with the snapshot's.
fn reset(vault_dir: &std::path::Path, snapshot: Option<&std::path::Path>) {
    for n in dir_names(vault_dir) {
        std::fs::remove_file(vault_dir.join(n)).unwrap();
    }
    if let Some(s) = snapshot {
        common::copy_dir(s, vault_dir);
    }
}

/// Reads the child's markers up to step `k`.
fn wait_for_step(out: &mut BufReader<std::process::ChildStdout>, k: u64, ctx: &str) {
    loop {
        let n: u64 = wait_for(out, "@@step ")
            .unwrap_or_else(|| panic!("{ctx}: the child stopped before step {k}"))
            .parse()
            .unwrap();
        if n >= k {
            return;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Found {
    Nothing,
    Old,
    New,
}

#[test]
fn kill_9_during_restore_leaves_the_old_or_the_new_vault() {
    let seed = seed();
    println!("restore crash seed: {seed} (replay with {SEED}={seed})");
    let mut rng = Rng(seed);

    let (f, mut v) = KitFixture::create();
    let backup = v.create_backup().unwrap();
    let new_items: Vec<ItemMeta> = v.items().to_vec();
    // The vault moves on after the backup.
    v.transact(|t| {
        let item = t.create_item(secret_item("later/item"))?;
        t.add_field(
            item,
            name("value"),
            SecretBytes::copy_from(b"a later value"),
        )?;
        Ok(())
    })
    .unwrap();
    let old_items: Vec<ItemMeta> = v.items().to_vec();
    let old_pass = v
        .unlockers()
        .find(|e| e.kind() == UnlockerKind::Passphrase)
        .unwrap()
        .to_bytes();
    drop(v);
    let snapshot = f.home.root().join("old-vault");
    common::copy_dir(&f.paths.vault_dir, &snapshot);
    assert_eq!(dir_names(&snapshot), ["vault.db"]);

    let new_pass = other_passphrase(9);
    let mut input = f.kit_text.as_bytes().to_vec();
    input.push(b'\n');
    // Test support: the passphrase crosses on stdin, never argv or env.
    let pass_text = "another passphrase, number 9";
    assert!(new_pass.ct_eq(pass_text.as_bytes()));
    input.extend_from_slice(pass_text.as_bytes());
    let data = f.paths.data_dir.to_str().unwrap().to_owned();
    let backup_path = backup.path.to_str().unwrap().to_owned();
    let env = [(RESTORER, data.as_str()), (BACKUP, backup_path.as_str())];

    // A full run, to time each step.
    reset(&f.paths.vault_dir, Some(&snapshot));
    let started = Instant::now();
    let mut child = spawn_self(&f.home, "restore_child", &env, &input);
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut at = [Duration::ZERO; STEPS as usize + 2];
    for k in 0..=STEPS {
        wait_for_step(&mut out, k, "timing run");
        at[k as usize] = started.elapsed();
    }
    assert!(wait_for(&mut out, "@@done").is_some());
    at[STEPS as usize + 1] = started.elapsed();
    kill_child(&mut child, "timing restorer");
    let gap = |k: u64| at[k as usize + 1].saturating_sub(at[k as usize]);

    let check = |ctx: &str, last: Option<u64>, had_old: bool| -> Found {
        let locked = match LockedVault::open(&f.paths) {
            Ok(l) => l,
            Err(e) => {
                assert!(!had_old, "{ctx}: the old vault is gone: {:?}", e.kind());
                assert_eq!(e.kind(), VaultErrorKind::NotFound, "{ctx}");
                assert!(
                    last.unwrap_or(0) < INSTALLED,
                    "{ctx}: installed, yet no vault"
                );
                return Found::Nothing;
            }
        };
        let names = dir_names(&f.paths.vault_dir);
        assert!(
            names.iter().all(|n| !n.starts_with(".vault.db.new-")),
            "{ctx}: temporary files left: {names:?}"
        );
        let v = locked.unlock(f.vmk()).map_err(|(_, e)| e).unwrap();
        assert_eq!(v.integrity(), Integrity::Ok, "{ctx}: the digest verifies");
        common::assert_holds_canaries(&v, &f.cs);
        let pass = v
            .unlockers()
            .find(|e| e.kind() == UnlockerKind::Passphrase)
            .unwrap()
            .to_bytes();
        if v.items() == &old_items[..] {
            assert!(had_old, "{ctx}");
            assert_eq!(pass, old_pass, "{ctx}: the old passphrase envelope");
            assert!(!v.recovery_confirmed().unwrap(), "{ctx}");
            assert!(last.unwrap_or(0) < INSTALLED, "{ctx}: installed, yet old");
            Found::Old
        } else {
            assert_eq!(v.items(), &new_items[..], "{ctx}: neither vault");
            assert_ne!(pass, old_pass, "{ctx}: the new passphrase envelope");
            assert!(v.recovery_confirmed().unwrap(), "{ctx}");
            assert!(
                last.unwrap_or(0) >= KEPT,
                "{ctx}: new before the old one was kept"
            );
            Found::New
        }
    };

    let (mut old, mut new, mut nothing) = (0, 0, 0);
    let mut landed = [0u32; STEPS as usize + 1];
    let rounds = (STEPS + 1) * ROUNDS_PER_TARGET;
    for round in 0..rounds + 8 {
        // The last eight rounds restore where there is no vault.
        let had_old = round < rounds;
        reset(&f.paths.vault_dir, had_old.then_some(snapshot.as_path()));
        let target = round % (STEPS + 1);
        let ctx = format!("seed {seed}: round {round}, after step {target}");
        let mut child = spawn_self(&f.home, "restore_child", &env, &input);
        let mut out = BufReader::new(child.stdout.take().unwrap());
        wait_for_step(&mut out, target, &ctx);
        let window = gap(target).as_micros() as u64;
        std::thread::sleep(Duration::from_micros(rng.below(window + 1)));
        kill_child(&mut child, "restorer");
        let text = rest(&mut out);
        let last = last_number(&text, "@@step ").or(Some(target));
        landed[last.unwrap() as usize] += 1;
        match check(&ctx, last, had_old) {
            Found::Old => old += 1,
            Found::New => new += 1,
            Found::Nothing => nothing += 1,
        }
    }
    println!(
        "restore kills: {old} left the old vault, {new} the new one, {nothing} no vault \
         (where none was); last step reached per kill: {landed:?}"
    );
    assert!(old > 0 && new > 0 && nothing > 0);
    // Kills landed between the step that keeps the old vault and the one
    // after the rename, where the files are swapped.
    assert!(landed[KEPT as usize] > 0, "{landed:?}");
    f.home.assert_clean(&f.cs);
}
