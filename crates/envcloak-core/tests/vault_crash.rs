//! Gate 5 (SPEC §15.2): after `kill -9` at 1,000 random points during
//! writes, the vault reopens at the last committed state with a valid
//! digest. Also: `kill -9` during `create` leaves no vault or a complete
//! one.
//!
//! The writer is this test binary, re-run as a child. It applies a seeded
//! workload, one transaction per write counter value, and prints each
//! commit. The parent kills it at a random moment, reopens the vault, and
//! checks that the counter is the last one printed (or the next, when the
//! kill landed between the commit and the print), that the digest
//! verifies, and that every item, value and prior value equals a model
//! replayed from the same seed. Set `ENVCLOAK_VAULT_CRASH_SEED` to replay a
//! run.
//!
//! Reopening the vault checkpoints and removes the WAL, so a writer the
//! parent starts next opens a clean file. To kill during WAL recovery too,
//! the parent sometimes starts another writer on the WAL the killed one
//! left, before reopening the vault itself, and kills it while it opens,
//! recovers and unlocks the vault.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::BTreeMap;
use std::io::BufReader;
use std::time::{Duration, Instant};

use common::{
    Fixture, Rng, dir_names, kill_child, last_number, name, read_stdin, rest, spawn_self, wait_for,
};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::{
    Argon2id, Envelope, EnvelopeCtx, KdfParams, UnlockerId, UnlockerKind, VaultId, Vmk,
    wrap_vmk_with,
};
use envcloak_core::vault::{
    INITIAL_EPOCH, Integrity, ItemDetails, LockedVault, ProjectKey, ProjectRecord, Slug, Txn,
    Vault, VaultError, VaultErrorKind, VaultPaths,
};
use envcloak_testkit::{TestHome, fresh_seed};

const WRITER: &str = "ENVCLOAK_VAULT_CRASH_WRITER";
const CREATOR: &str = "ENVCLOAK_VAULT_CRASH_CREATOR";
const SEED: &str = "ENVCLOAK_VAULT_CRASH_SEED";
const WORKERS: u64 = 4;
const KILLS_PER_WORKER: u32 = 250;

// ---- The seeded workload and its model ----

#[derive(Debug, Clone, Default, PartialEq)]
struct ModelField {
    value: Vec<u8>,
    /// Newest first, at most three.
    priors: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct ModelItem {
    title: String,
    fields: BTreeMap<String, ModelField>,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Model {
    items: BTreeMap<String, ModelItem>,
    projects: BTreeMap<Vec<u8>, u64>,
}

#[derive(Debug, Clone)]
enum Op {
    Create {
        slug: String,
        title: String,
        fields: Vec<(String, Vec<u8>)>,
    },
    AddField {
        slug: String,
        name: String,
        value: Vec<u8>,
    },
    SetValue {
        slug: String,
        name: String,
        value: Vec<u8>,
    },
    Retitle {
        slug: String,
        title: String,
    },
    Delete {
        slug: String,
    },
    Project {
        key: Vec<u8>,
        last_seen: u64,
    },
}

fn value(rng: &mut Rng) -> Vec<u8> {
    let len = match rng.below(20) {
        0 => 4_000 + rng.below(36_000),
        1..=5 => 200 + rng.below(3_800),
        _ => 8 + rng.below(192),
    };
    rng.text(len as usize)
}

/// The operations of the transaction that takes the write counter to `n`,
/// planned against the model before it. Each touches a different item.
fn plan(seed: u64, n: u64, m: &Model) -> Vec<Op> {
    let mut rng = Rng(seed ^ n.wrapping_mul(0x2545_f491_4f6c_dd1d));
    let mut ops = Vec::new();
    let mut touched = std::collections::BTreeSet::new();
    let slugs: Vec<&String> = m.items.keys().collect();
    let mut live = slugs.len();
    for k in 0..1 + rng.below(3) {
        let pick = if slugs.is_empty() {
            None
        } else {
            Some(slugs[rng.below(slugs.len() as u64) as usize].clone())
        };
        let roll = rng.below(100);
        match pick.filter(|s| roll >= 25 && !touched.contains(s)) {
            None => {
                let fields = (0..1 + rng.below(2))
                    .map(|i| (format!("f{i}"), value(&mut rng)))
                    .collect();
                ops.push(Op::Create {
                    slug: format!("w/i{n}-{k}"),
                    title: format!("title {n} {k}"),
                    fields,
                });
            }
            Some(slug) => {
                touched.insert(slug.clone());
                let item = &m.items[&slug];
                match roll {
                    25..=64 => {
                        let names: Vec<&String> = item.fields.keys().collect();
                        let name = names[rng.below(names.len() as u64) as usize].clone();
                        ops.push(Op::SetValue {
                            slug,
                            name,
                            value: value(&mut rng),
                        });
                    }
                    65..=74 => ops.push(Op::AddField {
                        slug,
                        name: format!("g{n}"),
                        value: value(&mut rng),
                    }),
                    75..=84 if live > 3 => {
                        live -= 1;
                        ops.push(Op::Delete { slug });
                    }
                    85..=92 => ops.push(Op::Retitle {
                        slug,
                        title: format!("retitled {n}"),
                    }),
                    _ => ops.push(Op::Project {
                        key: vec![b'p', (rng.below(4)) as u8],
                        last_seen: n,
                    }),
                }
            }
        }
    }
    ops
}

fn apply_model(m: &mut Model, ops: &[Op]) {
    for op in ops {
        match op {
            Op::Create {
                slug,
                title,
                fields,
            } => {
                let fields = fields
                    .iter()
                    .map(|(n, v)| {
                        (
                            n.clone(),
                            ModelField {
                                value: v.clone(),
                                priors: Vec::new(),
                            },
                        )
                    })
                    .collect();
                m.items.insert(
                    slug.clone(),
                    ModelItem {
                        title: title.clone(),
                        fields,
                    },
                );
            }
            Op::AddField { slug, name, value } => {
                let f = ModelField {
                    value: value.clone(),
                    priors: Vec::new(),
                };
                m.items
                    .get_mut(slug)
                    .unwrap()
                    .fields
                    .insert(name.clone(), f);
            }
            Op::SetValue { slug, name, value } => {
                let f = m.items.get_mut(slug).unwrap().fields.get_mut(name).unwrap();
                let old = std::mem::replace(&mut f.value, value.clone());
                f.priors.insert(0, old);
                f.priors.truncate(3);
            }
            Op::Retitle { slug, title } => {
                m.items.get_mut(slug).unwrap().title = title.clone();
            }
            Op::Delete { slug } => {
                m.items.remove(slug);
            }
            Op::Project { key, last_seen } => {
                m.projects.insert(key.clone(), *last_seen);
            }
        }
    }
}

fn apply_txn(t: &mut Txn<'_>, ops: &[Op]) -> Result<(), VaultError> {
    let id = |t: &Txn<'_>, slug: &str| t.item_id(&Slug::new(slug).unwrap()).unwrap();
    for op in ops {
        match op {
            Op::Create {
                slug,
                title,
                fields,
            } => {
                let item = t.create_item(envcloak_core::vault::NewItem {
                    details: ItemDetails {
                        title: title.clone(),
                        ..ItemDetails::default()
                    },
                    ..common::secret_item(slug)
                })?;
                for (n, v) in fields {
                    t.add_field(item, name(n), SecretBytes::copy_from(v))?;
                }
            }
            Op::AddField {
                slug,
                name: n,
                value,
            } => {
                let item = id(t, slug);
                t.add_field(item, name(n), SecretBytes::copy_from(value))?;
            }
            Op::SetValue {
                slug,
                name: n,
                value,
            } => {
                let item = id(t, slug);
                let field = t.field_id(item, &name(n)).unwrap();
                t.set_value(field, SecretBytes::copy_from(value))?;
            }
            Op::Retitle { slug, title } => {
                let item = id(t, slug);
                t.update_item(
                    item,
                    ItemDetails {
                        title: title.clone(),
                        ..ItemDetails::default()
                    },
                )?;
            }
            Op::Delete { slug } => {
                let item = id(t, slug);
                t.delete_item(item)?;
            }
            Op::Project { key, last_seen } => {
                t.upsert_project(ProjectRecord {
                    key: ProjectKey::new(key).unwrap(),
                    display_path: "/src/project".into(),
                    manifest_sha256: [0; 32],
                    bindings: Vec::new(),
                    last_seen: *last_seen,
                })?;
            }
        }
    }
    Ok(())
}

/// Advances `m`, which is at write counter `from`, to `to`.
fn advance(seed: u64, m: &mut Model, from: u64, to: u64) {
    for n in from + 1..=to {
        let ops = plan(seed, n, m);
        apply_model(m, &ops);
    }
}

/// Panics unless the vault holds exactly the model. Messages name items
/// and fields, never values.
fn assert_matches(v: &Vault, m: &Model, ctx: &str) {
    let slugs: Vec<&str> = v.items().iter().map(|i| i.slug.as_str()).collect();
    let want: Vec<&str> = m.items.keys().map(String::as_str).collect();
    assert_eq!(slugs, want, "{ctx}: items");
    for meta in v.items() {
        let mi = &m.items[meta.slug.as_str()];
        assert_eq!(meta.details.title, mi.title, "{ctx}: {} title", meta.slug);
        let names: Vec<&str> = meta.fields.iter().map(|f| f.name.as_str()).collect();
        let want: Vec<&str> = mi.fields.keys().map(String::as_str).collect();
        assert_eq!(names, want, "{ctx}: {} fields", meta.slug);
        for f in &meta.fields {
            let mf = &mi.fields[f.name.as_str()];
            let where_ = format!("{ctx}: {}#{}", meta.slug, f.name);
            assert!(
                v.read_value(f.id).unwrap().ct_eq(&mf.value),
                "{where_} value"
            );
            assert_eq!(usize::from(f.prior_count), mf.priors.len(), "{where_}");
            for (i, p) in mf.priors.iter().enumerate() {
                assert!(
                    v.read_prior(f.id, i).unwrap().ct_eq(p),
                    "{where_} prior {i}"
                );
            }
        }
    }
    let projects: BTreeMap<Vec<u8>, u64> = v
        .projects()
        .unwrap()
        .map(|(_, r)| (r.key.as_bytes().to_vec(), r.last_seen))
        .collect();
    assert_eq!(projects, m.projects, "{ctx}: projects");
}

fn seed() -> u64 {
    std::env::var(SEED)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(fresh_seed)
}

// ---- The writer child ----

/// Runs only as the child the tests below start.
#[test]
fn crash_writer() {
    let Some(dir) = std::env::var_os(WRITER) else {
        return;
    };
    let seed: u64 = std::env::var(SEED).unwrap().parse().unwrap();
    let vmk = Vmk::import_for_testing(&read_stdin()).unwrap();
    let paths = VaultPaths::under(dir);
    let mut v = LockedVault::open(&paths)
        .unwrap()
        .unlock(vmk)
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
    let mut n = v.header().unwrap().write_counter;
    let mut model = Model::default();
    advance(seed, &mut model, 1, n);
    println!("@@ready {n}");
    loop {
        n += 1;
        let ops = plan(seed, n, &model);
        v.transact(|t| apply_txn(t, &ops)).unwrap();
        apply_model(&mut model, &ops);
        println!("@@committed {n}");
    }
}

/// What one worker saw.
#[derive(Debug, Default)]
struct Tally {
    /// The write counter its vault ended at.
    counter: u64,
    /// Kills timed to land while the child started, opened and unlocked a
    /// clean vault.
    early: u32,
    /// Kills that landed inside a transaction, after at least one commit
    /// of that child had been seen.
    after_commits: u32,
    /// Extra kills of a writer started on the WAL a killed writer left.
    recoveries: u32,
    /// Those that landed before that writer reported it was ready: while
    /// it opened the vault, recovered the WAL or unlocked.
    recoveries_before_ready: u32,
}

/// One worker: its own vault, `KILLS_PER_WORKER` kill points, each checked
/// by reopening the vault.
///
/// Most kills wait for the child to report 0 to 3 commits and then land
/// at a uniformly random moment within one more commit's duration (a
/// moving average), so they fall inside writes on fast and slow disks
/// alike. One in ten lands while the child is still starting. After one
/// kill in four that left a non-empty WAL, a second writer is started on
/// it and killed within a start-up's duration, mostly while it recovers
/// the WAL, before the vault is reopened and checked.
fn crash_worker(seed: u64) -> Tally {
    let (f, v) = Fixture::create();
    drop(v);
    let data = f.data();
    let seed_text = seed.to_string();
    let mut rng = Rng(seed ^ 0x6b69_6c6c);
    let mut model = Model::default();
    let mut at = 1u64;
    let mut ready_time = Duration::from_millis(20);
    let mut commit_time = Duration::from_millis(5);
    let mut tally = Tally::default();
    for kill in 0..KILLS_PER_WORKER {
        let started = Instant::now();
        let mut child = spawn_self(
            &f.home,
            "crash_writer",
            &[(WRITER, &data), (SEED, &seed_text)],
            // The VMK crosses on stdin, never in argv or the environment.
            &f.vmk,
        );
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut reported = at;
        if rng.below(10) == 0 {
            tally.early += 1;
            let us = rng.below(ready_time.as_micros() as u64 + 1);
            std::thread::sleep(Duration::from_micros(us));
        } else {
            let ready = wait_for(&mut out, "@@ready ");
            let ready: u64 = ready
                .unwrap_or_else(|| panic!("seed {seed}: kill {kill}: the writer did not start"))
                .parse()
                .unwrap();
            ready_time = started.elapsed();
            assert_eq!(ready, at, "seed {seed}: kill {kill}");
            let skip = rng.below(4);
            let mut last = Instant::now();
            for _ in 0..skip {
                let n = wait_for(&mut out, "@@committed ").unwrap();
                reported = n.parse().unwrap();
                commit_time = (commit_time * 3 + last.elapsed()) / 4;
                last = Instant::now();
            }
            if skip > 0 {
                tally.after_commits += 1;
            }
            let us = rng.below(commit_time.as_micros() as u64 + 1);
            std::thread::sleep(Duration::from_micros(us));
        }
        kill_child(&mut child, "writer");
        let tail = rest(&mut out);
        if let Some(n) = last_number(&tail, "@@committed ") {
            reported = n;
        }
        let ctx = format!("seed {seed}: kill {kill}");

        let mut wal = f.db().into_os_string();
        wal.push("-wal");
        let hot = std::fs::metadata(&wal).is_ok_and(|m| m.len() > 0);
        if hot && rng.below(4) == 0 {
            tally.recoveries += 1;
            let mut child = spawn_self(
                &f.home,
                "crash_writer",
                &[(WRITER, &data), (SEED, &seed_text)],
                &f.vmk,
            );
            let mut out = BufReader::new(child.stdout.take().unwrap());
            let us = rng.below(ready_time.as_micros() as u64 + 1);
            std::thread::sleep(Duration::from_micros(us));
            kill_child(&mut child, "recovering writer");
            let text = rest(&mut out);
            match last_number(&text, "@@ready ") {
                None => tally.recoveries_before_ready += 1,
                Some(n) => {
                    assert!(
                        n == reported || n == reported + 1,
                        "{ctx}: recovered to {n}, last reported commit {reported}"
                    );
                    reported = n;
                }
            }
            if let Some(n) = last_number(&text, "@@committed ") {
                reported = n;
            }
        }

        let v = f.unlock();
        assert_eq!(v.integrity(), Integrity::Ok, "{ctx}");
        let k = v.header().unwrap().write_counter;
        assert!(
            k == reported || k == reported + 1,
            "{ctx}: counter {k}, last reported commit {reported}"
        );
        advance(seed, &mut model, at, k);
        at = k;
        assert_matches(&v, &model, &ctx);
    }
    tally.counter = at;
    tally
}

#[test]
fn kill_9_at_a_thousand_points_leaves_the_last_commit() {
    let base = seed();
    println!("gate 5 seed: {base} (replay with {SEED}={base})");
    let workers: Vec<_> = (0..WORKERS)
        .map(|w| {
            let s = base.wrapping_add(w);
            std::thread::spawn(move || crash_worker(s))
        })
        .collect();
    let (mut commits, mut early, mut after) = (0, 0, 0);
    let (mut recoveries, mut in_recovery) = (0, 0);
    for w in workers {
        let t = w.join().unwrap();
        commits += t.counter - 1;
        early += t.early;
        after += t.after_commits;
        recoveries += t.recoveries;
        in_recovery += t.recoveries_before_ready;
    }
    let kills = WORKERS * u64::from(KILLS_PER_WORKER);
    println!(
        "gate 5: {kills} kills ({early} during start-up, {after} after one or more commits), \
         {commits} commits survived; {recoveries} more kills of a writer started on a \
         killed writer's WAL, {in_recovery} of them before it was ready"
    );
    assert!(
        in_recovery > 0,
        "no kill landed before a writer started on a killed writer's WAL was ready"
    );
    // The kills landed among writes: the vaults moved on by more than one
    // commit per kill that waited for commits.
    assert!(
        commits >= u64::from(after),
        "{commits} commits, {after} kills"
    );
    assert!(early > 0 && after > 0);
}

// ---- kill -9 during create ----

/// Runs only as the child of the test below: creates a vault.
#[test]
fn crash_creator() {
    let Some(dir) = std::env::var_os(CREATOR) else {
        return;
    };
    let input = read_stdin();
    let vault_id = VaultId(input[..16].try_into().unwrap());
    let vmk = Vmk::import_for_testing(&input[16..48]).unwrap();
    let env = Envelope::from_bytes(&input[48..]).unwrap();
    println!("@@start");
    Vault::create(&VaultPaths::under(dir), vault_id, vmk, vec![env]).unwrap();
    println!("@@created");
    std::thread::sleep(Duration::from_secs(60));
}

#[test]
fn kill_9_during_create_leaves_no_vault_or_a_whole_one() {
    let seed = seed();
    let mut rng = Rng(seed);
    let home = TestHome::new();
    let vault_id = VaultId::generate();
    let vmk = Vmk::generate();
    let env = wrap_vmk_with(
        &vmk,
        &SecretBytes::copy_from(b"creator passphrase"),
        UnlockerKind::Passphrase,
        &EnvelopeCtx {
            vault_id,
            unlocker_id: UnlockerId::generate(),
            epoch: INITIAL_EPOCH,
        },
        &KdfParams::minimum(),
        &Argon2id,
    )
    .unwrap();
    let mut input = vault_id.0.to_vec();
    input.extend_from_slice(&vmk.export_for_testing());
    input.extend_from_slice(&env.to_bytes());

    let mut create_time = Duration::from_millis(30);
    let (mut none, mut whole) = (0, 0);
    for round in 0..40 {
        let dir = home.root().join(format!("d{round}"));
        let paths = VaultPaths::under(&dir);
        let mut child = spawn_self(
            &home,
            "crash_creator",
            &[(CREATOR, dir.to_str().unwrap())],
            &input,
        );
        let mut out = BufReader::new(child.stdout.take().unwrap());
        assert!(wait_for(&mut out, "@@start").is_some(), "round {round}");
        let started = Instant::now();
        if round == 0 {
            // Measure one whole create first.
            assert!(wait_for(&mut out, "@@created").is_some());
            create_time = started.elapsed();
        } else {
            let us = rng.below(create_time.as_micros() as u64 * 5 / 4 + 1);
            std::thread::sleep(Duration::from_micros(us));
        }
        kill_child(&mut child, "creator");
        let ctx = format!("seed {seed}: round {round}");
        let v = match LockedVault::open(&paths) {
            Ok(locked) => {
                whole += 1;
                let v = locked
                    .unlock(Vmk::import_for_testing(&input[16..48]).unwrap())
                    .map_err(|(_, e)| e)
                    .unwrap();
                assert_eq!(v.integrity(), Integrity::Ok, "{ctx}");
                assert_eq!(v.header().unwrap().write_counter, 1, "{ctx}");
                v
            }
            Err(e) => {
                assert_eq!(e.kind(), VaultErrorKind::NotFound, "{ctx}");
                none += 1;
                // A later create succeeds and clears what the killed one
                // left behind.
                let vmk2 = Vmk::import_for_testing(&input[16..48]).unwrap();
                let v = Vault::create(&paths, vault_id, vmk2, vec![env.clone()]).unwrap();
                assert_eq!(v.integrity(), Integrity::Ok, "{ctx}");
                v
            }
        };
        // Either way, nothing of the killed create is left: no temporary
        // file, and no second name for the vault.
        let names = dir_names(&paths.vault_dir);
        assert!(
            names.iter().all(|n| n == "vault.db" || n == "vault.db-wal"),
            "{ctx}: {names:?}"
        );
        drop(v);
        assert_eq!(dir_names(&paths.vault_dir), ["vault.db"], "{ctx}");
    }
    println!("create kills: {none} left no vault, {whole} left a whole one");
    assert!(
        none > 0,
        "no kill landed before the vault was linked into place"
    );
}
