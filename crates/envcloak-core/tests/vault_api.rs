//! Vault storage behavior: items, fields, prior values, projects, policies,
//! unlockers, the header, transactions, size caps and slug uniqueness.
#![allow(clippy::unwrap_used)]

mod common;

use common::{Fixture, dir_names, name, secret_item, slug};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::{
    Argon2id, EnvelopeCtx, ItemClass, KdfParams, UnlockerId, UnlockerKind, VaultId, Vmk,
    wrap_vmk_with,
};
use envcloak_core::vault::{
    AuditHead, INITIAL_EPOCH, Integrity, ItemDetails, LockedVault, MAX_FIELD, MAX_PRIOR, NewItem,
    PolicyId, PolicyRecord, ProjectBinding, ProjectKey, ProjectRecord, StandingBinding, Vault,
    VaultErrorKind,
};

fn value(s: &[u8]) -> SecretBytes {
    SecretBytes::copy_from(s)
}

fn envelope(
    f: &Fixture,
    vmk: &Vmk,
    kind: UnlockerKind,
    id: UnlockerId,
) -> envcloak_core::crypto::Envelope {
    wrap_vmk_with(
        vmk,
        &value(b"another test passphrase"),
        kind,
        &EnvelopeCtx {
            vault_id: f.vault_id,
            unlocker_id: id,
            epoch: INITIAL_EPOCH,
        },
        &KdfParams::minimum(),
        &Argon2id,
    )
    .unwrap()
}

#[test]
fn a_new_vault_is_empty_verified_and_durable() {
    let (f, v) = Fixture::create();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert!(v.items().is_empty());
    assert_eq!(v.header().unwrap().write_counter, 1);
    assert_eq!(v.schema_version(), 2);
    assert_eq!(v.epoch(), INITIAL_EPOCH);
    assert_eq!(v.vault_id(), f.vault_id);
    assert_eq!(v.unlockers().count(), 1);

    let r = v.storage_report().unwrap();
    assert_eq!(r.journal_mode, "wal");
    assert_eq!(r.locking_mode, "exclusive");
    assert_eq!(r.synchronous, 2, "FULL");
    assert_eq!(r.temp_store, 2, "MEMORY");
    assert!(r.secure_delete);
    assert!(r.defensive && !r.trusted_schema && !r.triggers_enabled && !r.views_enabled);
    // fullfsync exists only on macOS, where plain fsync does not flush the
    // drive cache.
    assert_eq!(r.fullfsync, cfg!(target_os = "macos"));
    assert_eq!(r.checkpoint_fullfsync, cfg!(target_os = "macos"));

    // The locked file lists its unlockers without the key.
    let locked = v.lock();
    assert_eq!(locked.unlockers().unwrap().len(), 1);
    assert_eq!(locked.vault_id(), f.vault_id);
    let v = locked.unlock(f.vmk()).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
}

#[test]
fn items_fields_and_values_round_trip() {
    let (f, mut v) = Fixture::create();
    let details = ItemDetails {
        title: "OpenAI (work)".into(),
        provider: Some("openai".into()),
        env_hint: Some("OPENAI_API_KEY".into()),
        allowed_hosts: vec!["api.openai.com".into()],
        tags: vec!["work".into()],
        ..ItemDetails::default()
    };
    let (item, key, org) = v
        .transact(|t| {
            let item = t.create_item(NewItem {
                class: ItemClass::Secret,
                slug: slug("openai/work"),
                details: details.clone(),
            })?;
            let key = t.add_field(item, name("api_key"), value(b"first value 0001"))?;
            let org = t.add_field(item, name("org"), value(b"org-value"))?;
            t.create_item(secret_item("a/first"))?;
            Ok((item, key, org))
        })
        .unwrap();
    assert_eq!(v.header().unwrap().write_counter, 2);
    let slugs: Vec<&str> = v.items().iter().map(|i| i.slug.as_str()).collect();
    assert_eq!(slugs, ["a/first", "openai/work"], "sorted by slug");
    let meta = v.find(&slug("openai/work")).unwrap();
    assert_eq!(meta.id, item);
    assert_eq!(meta.details, details);
    assert_eq!(meta.class, ItemClass::Secret);
    let names: Vec<&str> = meta.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["api_key", "org"], "sorted by name");
    assert_eq!(v.item(item).unwrap().slug, slug("openai/work"));
    assert!(v.read_value(key).unwrap().ct_eq(b"first value 0001"));
    assert!(v.read_value(org).unwrap().ct_eq(b"org-value"));

    // Everything survives a lock and unlock, and a reopen.
    let v = v.lock().unlock(f.vmk()).map_err(|(_, e)| e).unwrap();
    assert!(v.read_value(key).unwrap().ct_eq(b"first value 0001"));
    drop(v);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.find(&slug("openai/work")).unwrap().details, details);
    assert!(v.read_value(org).unwrap().ct_eq(b"org-value"));
}

#[test]
fn set_value_keeps_three_prior_values_newest_first() {
    let (f, mut v) = Fixture::create();
    let field = v
        .transact(|t| {
            let i = t.create_item(secret_item("svc/key"))?;
            t.add_field(i, name("value"), value(b"v0"))
        })
        .unwrap();
    for n in 1..=5u8 {
        v.transact(|t| t.set_value(field, value(&[b'v', b'0' + n])))
            .unwrap();
        let meta = &v.find(&slug("svc/key")).unwrap().fields[0];
        assert_eq!(usize::from(meta.prior_count), usize::from(n).min(MAX_PRIOR));
    }
    let v = {
        drop(v);
        f.unlock()
    };
    assert!(v.read_value(field).unwrap().ct_eq(b"v5"));
    for (i, want) in [b"v4", b"v3", b"v2"].iter().enumerate() {
        assert!(v.read_prior(field, i).unwrap().ct_eq(*want), "prior {i}");
    }
    assert_eq!(
        v.read_prior(field, 3).unwrap_err().kind(),
        VaultErrorKind::UnknownField
    );
}

#[test]
fn a_failed_transaction_changes_nothing() {
    let (f, mut v) = Fixture::create();
    let field = v
        .transact(|t| {
            let i = t.create_item(secret_item("keep/me"))?;
            t.add_field(i, name("value"), value(b"kept value"))
        })
        .unwrap();
    let before = v.header().unwrap();
    let err = v
        .transact(|t| -> Result<(), _> {
            t.create_item(secret_item("gone/soon"))?;
            t.set_value(field, value(b"never committed"))?;
            t.delete_item(t.item_id(&slug("keep/me")).unwrap())?;
            Err(VaultErrorKind::InvalidRecord.into())
        })
        .unwrap_err();
    assert_eq!(err.kind(), VaultErrorKind::InvalidRecord);
    assert_eq!(v.header().unwrap(), before);
    assert!(v.find(&slug("gone/soon")).is_none());
    assert!(v.read_value(field).unwrap().ct_eq(b"kept value"));
    drop(v);
    let v = f.unlock();
    assert_eq!(v.header().unwrap(), before);
    assert_eq!(v.items().len(), 1);
    assert!(v.read_value(field).unwrap().ct_eq(b"kept value"));
}

#[test]
fn slugs_and_field_names_are_unique() {
    let (_f, mut v) = Fixture::create();
    v.transact(|t| {
        let i = t.create_item(secret_item("dup/item"))?;
        t.add_field(i, name("value"), value(b"x"))
    })
    .unwrap();
    let e = v
        .transact(|t| t.create_item(secret_item("dup/item")))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::DuplicateSlug);
    let item = v.find(&slug("dup/item")).unwrap().id;
    let e = v
        .transact(|t| t.add_field(item, name("value"), value(b"y")))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::DuplicateField);
    // A rename onto a taken slug fails; onto a free one it works, and the
    // old slug is free again.
    let other = v
        .transact(|t| t.create_item(secret_item("other/item")))
        .unwrap();
    let e = v
        .transact(|t| t.rename_item(other, slug("dup/item")))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::DuplicateSlug);
    v.transact(|t| t.rename_item(other, slug("renamed/item")))
        .unwrap();
    v.transact(|t| t.create_item(secret_item("other/item")))
        .unwrap();
    assert!(v.find(&slug("renamed/item")).is_some());
    let e = v
        .transact(|t| {
            t.create_item(NewItem {
                class: ItemClass::None,
                ..secret_item("no/class")
            })
        })
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::InvalidRecord);
    let missing = envcloak_core::vault::ItemId::generate();
    let e = v
        .transact(|t| t.add_field(missing, name("v"), value(b"z")))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::UnknownItem);
}

#[test]
fn size_caps_hold() {
    let (_f, mut v) = Fixture::create();
    let item = v
        .transact(|t| t.create_item(secret_item("big/one")))
        .unwrap();
    // 64 KiB per sensitive field.
    let field = v
        .transact(|t| t.add_field(item, name("max"), value(&vec![b'a'; MAX_FIELD])))
        .unwrap();
    let e = v
        .transact(|t| t.add_field(item, name("over"), value(&vec![b'a'; MAX_FIELD + 1])))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::TooLarge);
    let e = v
        .transact(|t| t.set_value(field, value(&vec![b'b'; MAX_FIELD + 1])))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::TooLarge);
    let e = v
        .transact(|t| t.add_field(item, name("empty"), value(b"")))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::InvalidValue);
    // Three full-size prior values still fit the 1 MiB row cap.
    for c in *b"cdef" {
        v.transact(|t| t.set_value(field, value(&vec![c; MAX_FIELD])))
            .unwrap();
    }
    assert!(
        v.read_prior(field, 2)
            .unwrap()
            .ct_eq(&vec![b'c'; MAX_FIELD])
    );
    // Metadata, projects and policies have the same cap.
    let e = v
        .transact(|t| {
            t.update_item(
                item,
                ItemDetails {
                    notes: "n".repeat(MAX_FIELD),
                    ..ItemDetails::default()
                },
            )
        })
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::TooLarge);
    // A record within every bound of its kind, but larger than a column.
    let mut big = common::standing_record(1);
    if let PolicyRecord::StandingApproval(s) = &mut big {
        s.bindings = (0..200)
            .map(|n| StandingBinding {
                env_name: format!("{}_{n}", "V".repeat(400)),
                item: envcloak_core::vault::ItemId::generate(),
                field: envcloak_core::vault::FieldId::generate(),
            })
            .collect();
    }
    assert!(big.encode().len() > MAX_FIELD);
    let e = v
        .transact(|t| t.put_policy(PolicyId::generate(), &big))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::TooLarge);
    let e = v
        .transact(|t| {
            t.upsert_project(ProjectRecord {
                key: ProjectKey::new(b"k").unwrap(),
                display_path: "p".repeat(envcloak_core::vault::MAX_PROJECT),
                manifest_sha256: [0; 32],
                bindings: Vec::new(),
                last_seen: 0,
            })
        })
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::TooLarge);
}

#[test]
fn delete_update_and_find_by_value() {
    let (f, mut v) = Fixture::create();
    let shared = b"a value two items share";
    let (a, b, c) = v
        .transact(|t| {
            let a = t.create_item(secret_item("a/one"))?;
            let fa = t.add_field(a, name("value"), value(shared))?;
            let b = t.create_item(secret_item("b/two"))?;
            let fb = t.add_field(b, name("value"), value(shared))?;
            let fc = t.add_field(b, name("other"), value(b"something else"))?;
            // Visible inside the transaction too.
            assert_eq!(t.find_by_value(&value(shared)).len(), 2);
            Ok((fa, fb, fc))
        })
        .unwrap();
    let mut both = v.find_by_value(&value(shared));
    both.sort();
    let mut want = vec![a, b];
    want.sort();
    assert_eq!(
        both, want,
        "a value shared by two items is reported for both"
    );
    assert_eq!(v.find_by_value(&value(b"something else")), vec![c]);
    assert!(v.find_by_value(&value(b"nothing")).is_empty());

    let item = v.find(&slug("b/two")).unwrap().id;
    v.transact(|t| {
        t.update_item(
            item,
            ItemDetails {
                title: "new title".into(),
                rotated_at: Some(7),
                ..ItemDetails::default()
            },
        )
    })
    .unwrap();
    assert_eq!(v.find(&slug("b/two")).unwrap().details.title, "new title");
    v.transact(|t| t.delete_item(item)).unwrap();
    assert!(v.find(&slug("b/two")).is_none());
    assert_eq!(v.find_by_value(&value(shared)), vec![a]);
    assert_eq!(
        v.read_value(b).unwrap_err().kind(),
        VaultErrorKind::UnknownField
    );
    drop(v);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.items().len(), 1);
    assert_eq!(v.find_by_value(&value(shared)), vec![a]);
}

#[test]
fn projects_policies_and_header_fields_persist() {
    let (f, mut v) = Fixture::create();
    let key = ProjectKey::new(&[1, 2, 3, 4]).unwrap();
    let record = ProjectRecord {
        key: key.clone(),
        display_path: "/src/acme-web".into(),
        manifest_sha256: [7; 32],
        bindings: vec![ProjectBinding {
            env_name: "OPENAI_API_KEY".into(),
            reference: "openai/work".into(),
        }],
        last_seen: 11,
    };
    let policy = PolicyId::generate();
    let pid = v
        .transact(|t| {
            t.put_policy(policy, &common::standing_record(1))?;
            t.set_audit_head(AuditHead {
                seq: 42,
                mac: [9; 32],
            });
            t.set_recovery_confirmed(true);
            assert_eq!(t.bump_policy_epoch(), 1);
            t.upsert_project(record.clone())
        })
        .unwrap();
    // Upserting the same key updates the same record.
    let updated = ProjectRecord {
        last_seen: 12,
        ..record.clone()
    };
    let pid2 = v
        .transact(|t| {
            t.put_policy(policy, &common::standing_record(2))?;
            t.upsert_project(updated.clone())
        })
        .unwrap();
    assert_eq!(pid, pid2);
    drop(v);
    let mut v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.find_project(&key).unwrap().unwrap(), (pid, &updated));
    assert_eq!(v.projects().unwrap().count(), 1);
    let policies: Vec<_> = v.policies().unwrap().collect();
    assert_eq!(policies, [(policy, &common::standing_record(2))]);
    let h = v.header().unwrap();
    assert_eq!(h.audit_head.unwrap().seq, 42);
    assert!(h.recovery_confirmed);
    assert_eq!(h.policy_epoch, 1);
    assert!(v.transact(|t| t.delete_project(&key)).unwrap());
    assert!(!v.transact(|t| t.delete_project(&key)).unwrap());
    assert!(v.transact(|t| t.delete_policy(policy)).unwrap());
    drop(v);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.projects().unwrap().count(), 0);
    assert_eq!(v.policies().unwrap().count(), 0);
}

#[test]
fn unlockers_are_added_replaced_and_never_all_removed() {
    let (f, mut v) = Fixture::create();
    let vmk = f.vmk();
    let first = v.unlockers().next().unwrap().unlocker_id();
    let kit = UnlockerId::generate();
    v.transact(|t| t.add_unlocker(envelope(&f, &vmk, UnlockerKind::RecoveryKit, kit)))
        .unwrap();
    let e = v
        .transact(|t| t.add_unlocker(envelope(&f, &vmk, UnlockerKind::RecoveryKit, kit)))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::DuplicateUnlocker);
    let replacement = envelope(&f, &vmk, UnlockerKind::Passphrase, first);
    v.transact(|t| t.replace_unlocker(replacement.clone()))
        .unwrap();
    assert_eq!(v.unlocker(first), Some(&replacement));
    v.transact(|t| t.remove_unlocker(kit)).unwrap();
    let e = v.transact(|t| t.remove_unlocker(first)).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::LastUnlocker);
    let e = v.transact(|t| t.remove_unlocker(kit)).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::UnknownUnlocker);
    drop(v);
    let locked = LockedVault::open(&f.paths).unwrap();
    assert_eq!(locked.unlockers().unwrap(), vec![replacement]);
    let v = locked.unlock(f.vmk()).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.integrity(), Integrity::Ok);
}

#[test]
fn create_open_and_lock_refusals() {
    let (f, v) = Fixture::create();
    // A second handle, in this process or another, is refused while the
    // first is open, locked or not.
    assert_eq!(
        LockedVault::open(&f.paths).unwrap_err().kind(),
        VaultErrorKind::Busy
    );
    let locked = v.lock();
    assert_eq!(
        LockedVault::open(&f.paths).unwrap_err().kind(),
        VaultErrorKind::Busy
    );
    // A wrong key opens nothing.
    let (locked, e) = locked.unlock(Vmk::generate()).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::KeyMismatch);
    drop(locked);

    // Creating over an existing vault fails and leaves it alone.
    let vmk = Vmk::generate();
    let env = envelope(&f, &vmk, UnlockerKind::Passphrase, UnlockerId::generate());
    let e = Vault::create(&f.paths, f.vault_id, vmk, vec![env]).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::AlreadyExists);
    assert_eq!(f.unlock().integrity(), Integrity::Ok);

    // No vault at all.
    let empty = envcloak_testkit::TestHome::new();
    let paths = envcloak_core::vault::VaultPaths::under(empty.root().join("data"));
    assert_eq!(
        LockedVault::open(&paths).unwrap_err().kind(),
        VaultErrorKind::NotFound
    );

    // create needs at least one unlocker of the initial epoch.
    let e = Vault::create(&paths, VaultId::generate(), Vmk::generate(), Vec::new()).unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::InvalidRecord);
}

/// A kill between `create` linking its file into place and removing the
/// temporary name leaves a second name for the live vault. Opening, once
/// it holds the lock, removes it and any leftover temporary journal.
#[test]
fn opening_removes_what_an_interrupted_create_left() {
    use std::os::unix::fs::MetadataExt;
    let (f, v) = Fixture::create();
    drop(v);
    let dir = std::fs::canonicalize(&f.paths.vault_dir).unwrap();
    std::fs::hard_link(f.db(), dir.join(".vault.db.new-0011223344556677")).unwrap();
    std::fs::write(dir.join(".vault.db.new-8899aabbccddeeff-journal"), b"").unwrap();
    assert_eq!(std::fs::metadata(f.db()).unwrap().nlink(), 2);

    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert!(
        !dir_names(&dir)
            .iter()
            .any(|n| n.starts_with(".vault.db.new-"))
    );
    drop(v);
    assert_eq!(dir_names(&dir), ["vault.db"]);
    assert_eq!(std::fs::metadata(f.db()).unwrap().nlink(), 1);
}

#[test]
fn a_foreign_or_newer_file_is_refused() {
    let (f, v) = Fixture::create();
    drop(v);
    // A newer file names its version in both `meta` and the header. (One of
    // them alone is an altered row: vault_integrity.rs.)
    f.raw()
        .execute_batch(
            "UPDATE meta SET schema_version = 99; UPDATE header SET schema_version = 99;",
        )
        .unwrap();
    assert_eq!(
        LockedVault::open(&f.paths).unwrap_err().kind(),
        VaultErrorKind::UnsupportedVersion
    );
    // No row names a vault id.
    f.raw()
        .execute_batch(
            "UPDATE meta SET schema_version = 1; UPDATE header SET schema_version = 1; \
             UPDATE meta SET vault_id = x'00'; UPDATE header SET vault_id = x'00'; \
             UPDATE unlockers SET vault_id = x'00';",
        )
        .unwrap();
    assert_eq!(
        LockedVault::open(&f.paths).unwrap_err().kind(),
        VaultErrorKind::Damaged
    );
    let raw = f.raw();
    raw.execute("UPDATE meta SET vault_id = ?1", [&f.vault_id.0[..]])
        .unwrap();
    raw.pragma_update(None, "application_id", 7).unwrap();
    drop(raw);
    assert_eq!(
        LockedVault::open(&f.paths).unwrap_err().kind(),
        VaultErrorKind::Damaged
    );

    // Not a database at all.
    std::fs::write(f.db(), b"not a database, just text").unwrap();
    assert_eq!(
        LockedVault::open(&f.paths).unwrap_err().kind(),
        VaultErrorKind::Damaged
    );
}

#[test]
fn project_metadata_capacity_is_separate_from_secret_field_capacity() {
    let (f, mut v) = Fixture::create();
    let mut record = ProjectRecord {
        key: ProjectKey::new(b"capacity").unwrap(),
        display_path: String::new(),
        manifest_sha256: [0; 32],
        bindings: vec![],
        last_seen: 1,
    };
    // Version 1 layout: version, length-prefixed key and path, hash,
    // binding count and timestamp. Check the serialized boundary itself.
    let overhead = 1 + 4 + 8 + 4 + 32 + 4 + 8;
    record.display_path = "p".repeat(128 * 1024 - overhead);
    let id = v.transact(|t| t.upsert_project(record.clone())).unwrap();
    let mut over = record.clone();
    over.display_path.push('p');
    assert_eq!(
        v.transact(|t| t.upsert_project(over)).unwrap_err().kind(),
        VaultErrorKind::TooLarge
    );
    assert_eq!(v.find_project(&record.key).unwrap(), Some((id, &record)));
    let v = v.lock().unlock(f.vmk()).map_err(|(_, e)| e).unwrap();
    assert_eq!(v.find_project(&record.key).unwrap(), Some((id, &record)));
    assert_eq!(MAX_FIELD, 65536);
}
