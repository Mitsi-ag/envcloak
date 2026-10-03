//! Writes the vault files in this directory with the M1 build: the vault
//! format of schema version 1, as M1 shipped it (commit b643efb, the base
//! of plan task M2-07). They are the independent oracle of the M2-07
//! migration tests (`tests/m1_format.rs`): files the real M1 code wrote,
//! loaded as bytes (plan lesson L-02), not files this build's own code
//! writes in an older layout.
//!
//! This file is not compiled by later builds, whose API it no longer fits.
//! To write the files again, check out b643efb, copy this file to
//! `crates/envcloak-core/tests/generate.rs`, and run
//!
//! ```text
//! ENVCLOAK_WRITE_M1_FIXTURE=<empty private directory> \
//!   cargo test -p envcloak-core --test generate -- --ignored --exact write_m1_fixture
//! ```
//!
//! then copy what it wrote here: `vault.db`, `vault-policy.db`,
//! `backup.ecbackup` and the file backup `files-<time>-<id>.ecfiles`. No
//! value in them is shaped like a key: the VMK, the Recovery Kit's secret
//! and every value are derived at run time from the fixed labels below, by
//! the writer and by the tests alike, so no key-shaped literal is
//! committed.
#![allow(clippy::unwrap_used)]

mod common;

use envcloak_core::SecretBytes;
use envcloak_core::crypto::{
    Argon2id, EnvelopeCtx, ItemClass, KdfParams, UnlockerId, UnlockerKind, VaultId, Vmk,
    wrap_vmk_with,
};
use envcloak_core::file_backup::{BackupFile, FileBackupCreator, FileLeft};
use envcloak_core::file_backup_v2::CreatorKind;
use envcloak_core::vault::{
    Account, AuditHead, CURRENT_SCHEMA, Classification, FieldName, INITIAL_EPOCH, ItemDetails,
    Links, NewItem, PolicyId, ProjectBinding, ProjectKey, ProjectRecord, Slug, Vault, VaultPaths,
};
use sha2::{Digest, Sha256};

/// Secret items in the fixture, besides one card and one issuer credential.
const SECRETS: usize = 40;

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(format!("envcloak/test/m2-07/m1-fixture/{label}").as_bytes()).into()
}

/// A field's value: text no provider pattern matches.
fn value(n: usize, version: usize) -> String {
    format!("m1 fixture value {n:02} version {version}")
}

fn other(n: usize) -> String {
    format!("m1 fixture other {n:02}")
}

/// The contents of file `n` of the file backup.
fn file_content(n: usize) -> String {
    format!("M1_FIXTURE_FILE_{n}=m1 fixture file contents {n}\n")
}

fn details(n: usize) -> ItemDetails {
    let pick = |m: usize| n % m == 0;
    ItemDetails {
        title: format!("M1 item {n:02}"),
        provider: pick(2).then(|| "openai".to_owned()),
        account: Account {
            email: pick(3).then(|| format!("dev{n}@example.com")),
            label: pick(4).then(|| format!("label {n}")),
            org_id: pick(5).then(|| format!("org-{n}")),
        },
        env_hint: pick(2).then(|| format!("M1_VAR_{n:02}")),
        classification: match n % 3 {
            0 => Classification::Unknown,
            1 => Classification::Test,
            _ => Classification::Live,
        },
        allowed_hosts: if pick(2) {
            vec!["api.example.com".to_owned(), format!("h{n}.example.com")]
        } else {
            Vec::new()
        },
        allow_short: pick(7),
        tags: (0..n % 3).map(|t| format!("tag-{t}")).collect(),
        links: Links {
            docs: pick(2).then(|| "https://example.com/docs".to_owned()),
            billing: pick(3).then(|| "https://example.com/billing".to_owned()),
            keys_page: pick(4).then(|| "https://example.com/keys".to_owned()),
            dashboard: pick(5).then(|| "https://example.com/dash".to_owned()),
        },
        expires_at: pick(2).then_some(1_900_000_000 + n as u64),
        rotated_at: pick(3).then_some(1_700_000_000 + n as u64),
        last_used_at: pick(4).then_some(1_800_000_000 + n as u64),
        notes: format!("notes for item {n:02}"),
    }
}

#[test]
#[ignore = "writes the M1 fixture; run by hand at the M1 commit"]
fn write_m1_fixture() {
    assert_eq!(
        CURRENT_SCHEMA, 1,
        "the fixture is M1's format: run at b643efb"
    );
    let out = std::path::PathBuf::from(std::env::var_os("ENVCLOAK_WRITE_M1_FIXTURE").unwrap());
    let home = envcloak_testkit::TestHome::new();
    let paths = VaultPaths::under(home.root().join("data"));
    let vault_id = VaultId::generate();
    let vmk = Vmk::import_for_testing(&derived("vmk")).unwrap();
    let kit = SecretBytes::copy_from(&derived("kit")[..16]);
    let wrap = |secret: &SecretBytes, kind| {
        let ctx = EnvelopeCtx {
            vault_id,
            unlocker_id: UnlockerId::generate(),
            epoch: INITIAL_EPOCH,
        };
        wrap_vmk_with(&vmk, secret, kind, &ctx, &KdfParams::minimum(), &Argon2id).unwrap()
    };
    let envelopes = vec![
        wrap(
            &SecretBytes::copy_from(common::PASSPHRASE),
            UnlockerKind::Passphrase,
        ),
        wrap(&kit, UnlockerKind::RecoveryKit),
    ];
    let vmk2 = Vmk::import_for_testing(&derived("vmk")).unwrap();
    let mut v = Vault::create(&paths, vault_id, vmk2, envelopes).unwrap();
    v.transact(|t| {
        for n in 0..SECRETS {
            let item = t.create_item(NewItem {
                class: ItemClass::Secret,
                slug: Slug::new(&format!("m1/item-{n:02}")).unwrap(),
                details: details(n),
            })?;
            let f = t.add_field(
                item,
                FieldName::new("value").unwrap(),
                SecretBytes::copy_from(value(n, 0).as_bytes()),
            )?;
            t.set_value(f, SecretBytes::copy_from(value(n, 1).as_bytes()))?;
            t.add_field(
                item,
                FieldName::new("other").unwrap(),
                SecretBytes::copy_from(other(n).as_bytes()),
            )?;
        }
        for (class, slug) in [
            (ItemClass::Card, "m1/card"),
            (ItemClass::IssuerCredential, "m1/issuer"),
        ] {
            let item = t.create_item(NewItem {
                class,
                slug: Slug::new(slug).unwrap(),
                details: ItemDetails {
                    title: slug.to_owned(),
                    ..ItemDetails::default()
                },
            })?;
            t.add_field(
                item,
                FieldName::new("value").unwrap(),
                SecretBytes::copy_from(format!("m1 fixture {slug}").as_bytes()),
            )?;
        }
        t.upsert_project(ProjectRecord {
            key: ProjectKey::new(b"m1 fixture project key").unwrap(),
            display_path: "/src/m1-fixture".to_owned(),
            manifest_sha256: derived("manifest"),
            bindings: vec![
                ProjectBinding {
                    env_name: "M1_VAR_00".to_owned(),
                    reference: "m1/item-00".to_owned(),
                },
                ProjectBinding {
                    env_name: "M1_OTHER".to_owned(),
                    reference: "m1/item-01#other".to_owned(),
                },
            ],
            last_seen: 1_750_000_000,
        })?;
        t.set_recovery_confirmed(true);
        t.bump_policy_epoch();
        t.bump_policy_epoch();
        t.set_audit_head(AuditHead {
            seq: 42,
            mac: derived("audit-mac"),
        });
        Ok(())
    })
    .unwrap();
    // A file backup, as `envcloak init` writes before it deletes a
    // plaintext file: `init --undo` must still open it once the vault has
    // moved to a newer schema, for its 7 days.
    let files = v
        .backup_files(
            &[
                BackupFile {
                    path: "/src/m1-fixture/.env".to_owned(),
                    mode: 0o600,
                    content: SecretBytes::copy_from(file_content(0).as_bytes()),
                    left: Some(FileLeft::Removed),
                },
                BackupFile {
                    path: "/src/m1-fixture/.env.local".to_owned(),
                    mode: 0o640,
                    content: SecretBytes::copy_from(file_content(1).as_bytes()),
                    left: Some(FileLeft::Rewritten(derived("rewritten"))),
                },
            ],
            &FileBackupCreator {
                kind: CreatorKind::Terminal,
                agent: None,
            },
        )
        .unwrap();
    std::fs::copy(&files.path, out.join(files.path.file_name().unwrap())).unwrap();
    let backup = v.create_backup().unwrap();
    std::fs::copy(&backup.path, out.join("backup.ecbackup")).unwrap();
    drop(v);
    let db = std::fs::canonicalize(&paths.vault_dir)
        .unwrap()
        .join("vault.db");
    std::fs::copy(&db, out.join("vault.db")).unwrap();

    // The same vault with one policy row, whose body M1 left to the
    // policy layer (M1 itself never wrote one).
    let mut v = envcloak_core::vault::LockedVault::open(&paths)
        .unwrap()
        .unlock(Vmk::import_for_testing(&derived("vmk")).unwrap())
        .map_err(|(_, e)| e)
        .unwrap();
    v.transact(|t| t.put_policy(PolicyId::generate(), b"an M1 policy body"))
        .unwrap();
    drop(v);
    std::fs::copy(&db, out.join("vault-policy.db")).unwrap();
}
