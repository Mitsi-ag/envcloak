//! Vault storage behavior: items, fields, prior values, projects, policies,
//! unlockers, the header, transactions, size caps and slug uniqueness.
#![allow(clippy::unwrap_used)]

mod common;

use common::{Fixture, name, secret_item, slug};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::{
    Argon2id, EnvelopeCtx, ItemClass, KdfParams, UnlockerId, UnlockerKind, VaultId, Vmk,
    wrap_vmk_with,
};
use envcloak_core::vault::{
    AuditHead, INITIAL_EPOCH, Integrity, ItemDetails, LockedVault, MAX_FIELD, MAX_PRIOR, NewItem,
    PolicyId, ProjectBinding, ProjectKey, ProjectRecord, Vault, VaultErrorKind,
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
    assert_eq!(v.header().write_counter, 1);
    assert_eq!(v.schema_version(), 1);
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
    assert_eq!(v.header().write_counter, 2);
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
    let before = v.header();
    let err = v
        .transact(|t| -> Result<(), _> {
            t.create_item(secret_item("gone/soon"))?;
            t.set_value(field, value(b"never committed"))?;
            t.delete_item(t.item_id(&slug("keep/me")).unwrap())?;
            Err(VaultErrorKind::InvalidRecord.into())
        })
        .unwrap_err();
    assert_eq!(err.kind(), VaultErrorKind::InvalidRecord);
    assert_eq!(v.header(), before);
    assert!(v.find(&slug("gone/soon")).is_none());
    assert!(v.read_value(field).unwrap().ct_eq(b"kept value"));
    drop(v);
    let v = f.unlock();
    assert_eq!(v.header(), before);
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
    for c in [b'c', b'd', b'e', b'f'] {
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
    let e = v
        .transact(|t| t.put_policy(PolicyId::generate(), &vec![0; MAX_FIELD + 1]))
        .unwrap_err();
    assert_eq!(e.kind(), VaultErrorKind::TooLarge);
    let e = v
        .transact(|t| {
            t.upsert_project(ProjectRecord {
                key: ProjectKey::new(b"k").unwrap(),
                display_path: "p".repeat(MAX_FIELD),
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
            t.put_policy(policy, b"policy body v1")?;
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
            t.put_policy(policy, b"policy body v2")?;
            t.upsert_project(updated.clone())
        })
        .unwrap();
    assert_eq!(pid, pid2);
    drop(v);
    let mut v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.find_project(&key).unwrap(), (pid, &updated));
    assert_eq!(v.projects().count(), 1);
    let policies: Vec<_> = v.policies().collect();
    assert_eq!(policies, [(policy, &b"policy body v2"[..])]);
    let h = v.header();
    assert_eq!(h.audit_head.unwrap().seq, 42);
    assert!(h.recovery_confirmed);
    assert_eq!(h.policy_epoch, 1);
    assert!(v.transact(|t| t.delete_project(&key)).unwrap());
    assert!(!v.transact(|t| t.delete_project(&key)).unwrap());
    assert!(v.transact(|t| t.delete_policy(policy)).unwrap());
    drop(v);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.projects().count(), 0);
    assert_eq!(v.policies().count(), 0);
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

#[test]
fn a_foreign_or_newer_file_is_refused() {
    let (f, v) = Fixture::create();
    drop(v);
    let raw = f.raw();
    raw.execute("UPDATE meta SET schema_version = 99", [])
        .unwrap();
    drop(raw);
    assert_eq!(
        LockedVault::open(&f.paths).unwrap_err().kind(),
        VaultErrorKind::UnsupportedVersion
    );
    let raw = f.raw();
    raw.execute("UPDATE meta SET schema_version = 0", [])
        .unwrap();
    drop(raw);
    assert_eq!(
        LockedVault::open(&f.paths).unwrap_err().kind(),
        VaultErrorKind::Damaged
    );
    let raw = f.raw();
    raw.execute("UPDATE meta SET schema_version = 1", [])
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
