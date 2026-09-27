//! Gate 2, storage part (SPEC §15.2): no fixture appears in the SQLite
//! main, WAL, shared-memory or journal bytes, raw or in any listed encoding.
//!
//! The vault directory is swept while the vault is open (the WAL holds the
//! latest frames), after it is closed (the WAL has been checkpointed into
//! the main file), and after a writer is killed mid-transaction (the WAL
//! holds frames that never committed). A positive control shows the sweep
//! finds a value SQLite stores in plaintext.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::BufReader;
use std::time::Duration;

use common::{Fixture, Rng, kill_child, name, read_stdin, secret_item, spawn_self, wait_for};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::Vmk;
use envcloak_core::vault::{FieldId, Integrity, LockedVault, Vault, VaultPaths};
use envcloak_testkit::{
    Canary, Hit, assert_sweep_clean, by_label, canaries, fresh_seed, labels, sweep_dir,
};

fn value(c: &Canary) -> SecretBytes {
    SecretBytes::copy_from(c.value())
}

/// Stores every fixture: each canary as a field value, the OpenAI key
/// rotated so the old and new keys are a value and a prior value, and one
/// item created and deleted.
fn store_every_fixture(v: &mut Vault, cs: &[Canary]) -> Vec<(FieldId, String)> {
    v.transact(|t| {
        let mut ids = Vec::new();
        for (n, c) in cs.iter().enumerate() {
            let item = t.create_item(secret_item(&format!("fixture/item-{n}")))?;
            let id = t.add_field(item, name("value"), value(c))?;
            ids.push((id, c.label.clone()));
        }
        let doomed = t.create_item(secret_item("fixture/deleted"))?;
        t.add_field(
            doomed,
            name("value"),
            value(by_label(cs, labels::GITHUB_TOKEN)),
        )?;
        t.delete_item(doomed)?;
        Ok(ids)
    })
    .unwrap()
}

#[test]
fn values_never_reach_the_database_files() {
    let cs = canaries(fresh_seed());
    let (f, mut v) = Fixture::create();
    let ids = store_every_fixture(&mut v, &cs);
    let openai = ids
        .iter()
        .find(|(_, l)| l == labels::OPENAI_API_KEY)
        .unwrap()
        .0;
    v.transact(|t| t.set_value(openai, value(by_label(&cs, labels::OPENAI_API_KEY_ROTATED))))
        .unwrap();
    // Reads and lookups too.
    for (id, label) in &ids {
        let want = if label == labels::OPENAI_API_KEY {
            labels::OPENAI_API_KEY_ROTATED
        } else {
            label
        };
        assert!(
            v.read_value(*id)
                .unwrap()
                .ct_eq(by_label(&cs, want).value())
        );
    }
    assert!(
        v.read_prior(openai, 0)
            .unwrap()
            .ct_eq(by_label(&cs, labels::OPENAI_API_KEY).value())
    );
    assert_eq!(
        v.find_by_value(&value(by_label(&cs, labels::STRIPE_SECRET_KEY)))
            .len(),
        1
    );

    // Open: the WAL holds the writes.
    let wal = std::fs::canonicalize(&f.paths.vault_dir)
        .unwrap()
        .join("vault.db-wal");
    assert!(std::fs::metadata(&wal).unwrap().len() > 0);
    assert_sweep_clean(&f.paths.data_dir, &cs);

    // Locked, still open.
    let locked = v.lock();
    assert_sweep_clean(&f.paths.data_dir, &cs);

    // Closed: checkpointed into the main file.
    drop(locked);
    assert!(!wal.exists());
    assert_sweep_clean(&f.paths.data_dir, &cs);
    // And the whole test home.
    f.home.assert_clean(&cs);

    // Reopened, every value is still there.
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items().len(), cs.len());
}

#[test]
fn the_sweep_finds_a_value_sqlite_stores_in_plaintext() {
    // Positive control for the test above: the same sweep, over a SQLite
    // file in WAL mode that holds a fixture unsealed, reports it in the
    // WAL and, once checkpointed, in the main file.
    let cs = canaries(fresh_seed());
    let home = envcloak_testkit::TestHome::new();
    let dir = home.root().join("control");
    std::fs::create_dir(&dir).unwrap();
    let conn = rusqlite::Connection::open(dir.join("plain.db")).unwrap();
    conn.pragma_update(None, "journal_mode", "wal").unwrap();
    conn.execute_batch("CREATE TABLE t (v BLOB)").unwrap();
    conn.execute(
        "INSERT INTO t VALUES (?1)",
        [by_label(&cs, labels::DATABASE_URL).value()],
    )
    .unwrap();
    let found_in = |hits: &[Hit], file: &str| {
        hits.iter().any(|h| match h {
            Hit::Canary { path, found } => {
                path.raw().file_name().is_some_and(|n| n == file)
                    && found.label == labels::DATABASE_URL
            }
            _ => false,
        })
    };
    let open = sweep_dir(&dir, &cs);
    assert!(found_in(&open, "plain.db-wal"), "{open:?}");
    drop(conn);
    let closed = sweep_dir(&dir, &cs);
    assert!(found_in(&closed, "plain.db"), "{closed:?}");
}

const WRITER: &str = "ENVCLOAK_VAULT_BYTES_WRITER";
const SEED: &str = "ENVCLOAK_VAULT_BYTES_SEED";

/// Runs only as the child of the test below: writes fixtures in a loop.
#[test]
fn fixture_writer() {
    let Some(dir) = std::env::var_os(WRITER) else {
        return;
    };
    let seed: u64 = std::env::var(SEED).unwrap().parse().unwrap();
    let cs = canaries(seed);
    let vmk = Vmk::import_for_testing(&read_stdin()).unwrap();
    let mut v = LockedVault::open(&VaultPaths::under(dir))
        .unwrap()
        .unlock(vmk)
        .map_err(|(_, e)| e)
        .unwrap();
    let mut rng = Rng(seed);
    // Earlier children's items remain: slugs start from this run's counter.
    let base = v.header().write_counter;
    println!("@@ready");
    // Runs until the parent kills it.
    let mut n = 0u64;
    loop {
        n += 1;
        let c = &cs[rng.below(cs.len() as u64) as usize];
        v.transact(|t| {
            let item = t.create_item(secret_item(&format!("w/{base}-{n}")))?;
            let field = t.add_field(item, name("value"), value(c))?;
            let other = &cs[(n as usize + 1) % cs.len()];
            t.set_value(field, value(other))?;
            if n % 3 == 0 {
                t.delete_item(item)?;
            }
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn a_killed_writer_leaves_no_value_in_any_file() {
    let seed = fresh_seed();
    let cs = canaries(seed);
    let (f, v) = Fixture::create();
    drop(v);
    let mut rng = Rng(seed);
    for round in 0..20 {
        let mut child = spawn_self(
            &f.home,
            "fixture_writer",
            &[(WRITER, &f.data()), (SEED, &seed.to_string())],
            &f.vmk,
        );
        let mut out = BufReader::new(child.stdout.take().unwrap());
        assert!(wait_for(&mut out, "@@ready").is_some(), "round {round}");
        std::thread::sleep(Duration::from_micros(rng.below(30_000)));
        kill_child(&mut child, "fixture writer");
        // The WAL, and whatever else the kill left, as it is on disk.
        assert_sweep_clean(&f.paths.data_dir, &cs);
        // Recovery at the next open checkpoints nothing new into view.
        let v = f.unlock();
        assert_eq!(v.integrity(), Integrity::Ok, "round {round}");
        drop(v);
        assert_sweep_clean(&f.paths.data_dir, &cs);
    }
    f.home.assert_clean(&cs);
}
