//! Schema version 2's records through the public vault API (plan task
//! M2-07): login items and their typed fields, typed policy records and
//! the standing set, and item record v2's exposure and classification
//! time.
//!
//! - A login's ciphertext moved into a secret item's row does not open
//!   there: the `login` class is in the associated data of every sealed
//!   column, so a vault that turns read-only for its owner to recover what
//!   it holds still never serves a login's value as another item's.
//! - A login's values are hashed in a domain of their own: no comparison
//!   against the vault's values matches one.
//! - A policy row of an unknown kind or version, or one that does not
//!   decode whole, is refused like tampering: never read as an empty or a
//!   default record.
//! - The standing set's generation moves once per transaction that changes
//!   a standing approval, and only then.
#![allow(clippy::unwrap_used)]

mod common;

use common::{Fixture, name, secret_item, slug, standing_record};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{
    BindingStrength, Classification, CodeDigest, DirIdentity, ExposureSource, FieldKind,
    FileIdentity, Integrity, ItemDetails, LaunchClass, LaunchDecl, LaunchEnv, LoginMeta, LoginTier,
    ManagedServer, ManagedTransport, NewLogin, PolicyId, PolicyRecord, ProjectIdentity,
    RegisteredLaunch, SubjectKindRecord, TamperKind, TotpAlgorithm, TotpEnrollment, TotpParams,
    VaultErrorKind,
};

const PASSWORD: &[u8] = b"a login password moved around";

fn login(slug_text: &str) -> NewLogin {
    NewLogin {
        slug: slug(slug_text),
        details: ItemDetails {
            title: "fixture editor".into(),
            classification: Classification::Test,
            ..ItemDetails::default()
        },
        meta: LoginMeta {
            tier: LoginTier::Dev,
            session_lifetime: 900,
        },
        username: SecretBytes::copy_from(b"editor@example.test"),
        password: SecretBytes::copy_from(PASSWORD),
        totp: Some(TotpEnrollment {
            params: TotpParams::new(TotpAlgorithm::Sha1, 6, 30).unwrap(),
            seed: SecretBytes::copy_from(b"a totp seed of the login"),
        }),
        adapter_key: Some(SecretBytes::copy_from(b"an adapter key of the login")),
    }
}

fn managed_record() -> PolicyRecord {
    PolicyRecord::ManagedServer(ManagedServer {
        name: "claude-code/github".into(),
        project: ProjectIdentity {
            canonical_dir: b"/data/mcp/claude-code-github".to_vec(),
            dev: 3,
            ino: 4,
        },
        transport: ManagedTransport::Stdio(Box::new(RegisteredLaunch {
            launch_id: [7; 16],
            revision: 1,
            class: LaunchClass::Native,
            executable: FileIdentity {
                path: b"/usr/local/bin/github-mcp-server".to_vec(),
                dev: 1,
                ino: 2,
                digest: CodeDigest::Sha256([8; 32]),
            },
            argv: vec![b"github-mcp-server".to_vec(), b"stdio".to_vec()],
            cwd: DirIdentity {
                path: b"/data/mcp/claude-code-github".to_vec(),
                dev: 3,
                ino: 4,
            },
            env: LaunchEnv {
                path_env: b"/usr/local/bin:/usr/bin".to_vec(),
                vars: vec![("LOG_LEVEL".into(), "info".into())],
                binding_names: vec!["GITHUB_TOKEN".into()],
            },
            entry: None,
            strength: BindingStrength::Bound,
            declaration: LaunchDecl {
                argv: vec!["github-mcp-server".into(), "stdio".into()],
                cwd: None,
                env: vec![("LOG_LEVEL".into(), "info".into())],
                path_env: Some("/usr/local/bin:/usr/bin".into()),
            },
        })),
        registered_by: SubjectKindRecord::Terminal,
        written_by_migrate_mcp: true,
    })
}

/// The plan's moved-ciphertext test: a login's password field row moved to
/// a secret item (same row id, row version and column, so only the item
/// class differs) does not open there. The vault turns read-only, as any
/// moved row makes it, and still serves what opens for its owner to
/// recover; the login's password is not among it, under any item.
#[test]
fn a_login_ciphertext_moved_into_a_secret_row_does_not_open() {
    let (f, mut v) = Fixture::create();
    let (secret, login_id) = v
        .transact(|t| {
            let s = t.create_item(secret_item("openai/work"))?;
            t.add_field(s, name("value"), SecretBytes::copy_from(b"a secret value"))?;
            let l = t.create_login(login("fixture/editor"))?;
            Ok((s, l))
        })
        .unwrap();
    let password = v
        .item(login_id)
        .unwrap()
        .fields
        .iter()
        .find(|f| f.kind == FieldKind::Password)
        .unwrap()
        .id;
    drop(v);
    let raw = f.raw();
    let n = raw
        .execute(
            "UPDATE fields SET item_id = ?1 WHERE id = ?2",
            rusqlite::params![&secret.as_bytes()[..], &password.as_bytes()[..]],
        )
        .unwrap();
    assert_eq!(n, 1);
    drop(raw);

    let v = f.unlock();
    // The moved row does not open under the secret item's class: that is
    // the first finding, before the digest's.
    assert_eq!(
        v.integrity(),
        Integrity::Tampered(TamperKind::RowUnreadable)
    );
    let s = v.item(secret).unwrap();
    assert_eq!(s.fields.len(), 1, "the moved login field is not listed");
    for item in v.items() {
        for field in &item.fields {
            if let Ok(got) = v.read_value(field.id) {
                assert!(!got.ct_eq(PASSWORD), "{}#{}", item.slug, field.name);
            }
        }
    }
    let l = v.item(login_id).unwrap();
    assert!(l.fields.iter().all(|f| f.kind != FieldKind::Password));
}

/// No comparison against the vault's values matches a login's: the
/// password stored as a secret's value too is found once, as the secret's.
#[test]
fn a_login_value_never_matches_a_comparison() {
    let (_f, mut v) = Fixture::create();
    let secret_field = v
        .transact(|t| {
            t.create_login(login("fixture/editor"))?;
            let s = t.create_item(secret_item("same/value"))?;
            t.add_field(s, name("value"), SecretBytes::copy_from(PASSWORD))
        })
        .unwrap();
    let found = v.find_by_value(&SecretBytes::copy_from(PASSWORD));
    assert_eq!(found, [secret_field]);
    for other in [
        &b"editor@example.test"[..],
        b"an adapter key of the login",
        b"a totp seed of the login",
    ] {
        assert!(v.find_by_value(&SecretBytes::copy_from(other)).is_empty());
    }
}

/// A policy row that is not a record this build knows is refused like
/// tampering: the vault opens read-only and serves no policy. Never read
/// as nothing, or as a default record. The control, a known record, opens.
#[test]
fn a_policy_of_an_unknown_kind_or_version_is_refused_like_tampering() {
    let valid = standing_record(3).encode();
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut kind_9 = valid.clone();
    kind_9[0] = 9;
    let mut version_2 = valid.clone();
    version_2[1] = 2;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("an unknown kind", kind_9),
        ("an unknown version", version_2),
        ("kind 0", vec![0, 1]),
        ("no bytes", Vec::new()),
        ("a kind alone", vec![1]),
        ("trailing bytes", trailing),
        ("cut short", valid[..valid.len() - 1].to_vec()),
        ("the reserved standing-set kind", vec![4, 1]),
    ];
    for (case, body) in cases {
        let (f, mut v) = Fixture::create();
        v.transact(|t| {
            t.put_policy(PolicyId::generate(), &standing_record(1))?;
            t.put_raw_policy_for_testing(PolicyId::generate(), &body)
        })
        .unwrap();
        drop(v);
        let v = f.unlock();
        assert_eq!(
            v.integrity(),
            Integrity::Tampered(TamperKind::RowInconsistent),
            "{case}"
        );
        assert_eq!(
            v.policies().err().unwrap().kind(),
            VaultErrorKind::Tampered,
            "{case}"
        );
    }
    // Control: the same path with a record this build knows.
    let (f, mut v) = Fixture::create();
    v.transact(|t| t.put_raw_policy_for_testing(PolicyId::generate(), &valid))
        .unwrap();
    drop(v);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    let got: Vec<_> = v.policies().unwrap().map(|(_, r)| r.clone()).collect();
    assert_eq!(got, [standing_record(3)]);
}

/// The standing set moves by one per transaction that adds, replaces or
/// removes a standing approval, never for another kind, and its digest is
/// the set's: equal sets, equal digests.
#[test]
fn the_standing_set_moves_with_the_standing_approvals_only() {
    let (f, mut v) = Fixture::create();
    let start = v.standing_set().unwrap();
    assert_eq!(start.generation, 0);
    let (a, b, m) = (
        PolicyId::generate(),
        PolicyId::generate(),
        PolicyId::generate(),
    );
    let generation = |v: &envcloak_core::vault::Vault| v.standing_set().unwrap().generation;

    v.transact(|t| t.put_policy(m, &managed_record())).unwrap();
    assert_eq!(
        v.standing_set().unwrap(),
        start,
        "a managed server is not standing"
    );
    v.transact(|t| {
        t.put_policy(a, &standing_record(1))?;
        t.put_policy(b, &standing_record(2))
    })
    .unwrap();
    assert_eq!(generation(&v), 1, "one transaction, one generation");
    let with_both = v.standing_set().unwrap().set_digest;
    assert_ne!(with_both, start.set_digest);
    v.transact(|t| t.put_policy(a, &standing_record(4)))
        .unwrap();
    assert_eq!(generation(&v), 2);
    assert_ne!(v.standing_set().unwrap().set_digest, with_both);
    v.transact(|t| t.put_policy(a, &standing_record(1)))
        .unwrap();
    assert_eq!(generation(&v), 3);
    assert_eq!(
        v.standing_set().unwrap().set_digest,
        with_both,
        "the digest is the set's, whatever the history"
    );
    // A transaction that changes no standing approval keeps the set.
    v.transact(|t| {
        t.delete_policy(m)?;
        t.bump_policy_epoch();
        Ok(())
    })
    .unwrap();
    assert_eq!(generation(&v), 3);
    // A standing approval replaced by another kind, and one removed.
    v.transact(|t| t.put_policy(b, &managed_record())).unwrap();
    assert_eq!(generation(&v), 4);
    v.transact(|t| t.delete_policy(a)).unwrap();
    assert_eq!(generation(&v), 5);
    let last = v.standing_set().unwrap();
    assert_eq!(last.set_digest, start.set_digest, "the empty set again");
    drop(v);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    assert_eq!(v.standing_set().unwrap(), last);
}

/// A policy record out of its kind's bounds is refused before anything is
/// written.
#[test]
fn a_policy_out_of_bounds_is_refused_unwritten() {
    let (f, mut v) = Fixture::create();
    let mut no_bindings = standing_record(1);
    if let PolicyRecord::StandingApproval(s) = &mut no_bindings {
        s.bindings.clear();
    }
    let mut script_without_entry = managed_record();
    if let PolicyRecord::ManagedServer(ManagedServer {
        transport: ManagedTransport::Stdio(l),
        ..
    }) = &mut script_without_entry
    {
        l.class = LaunchClass::Script;
    }
    for bad in [no_bindings, script_without_entry] {
        let e = v
            .transact(|t| t.put_policy(PolicyId::generate(), &bad))
            .unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::InvalidRecord);
    }
    drop(v);
    let v = f.unlock();
    assert_eq!(v.policies().unwrap().count(), 0);
}

/// Item record v2: an exposure only grows (its first time kept, the kinds
/// joined, the counts summed) and sets the rotation flag; clearing it
/// clears both. The classification's last change is recorded at creation
/// and at every change, and only then. Both survive a reopen.
#[test]
fn exposure_and_the_classification_time_are_kept_by_the_vault() {
    let (f, mut v) = Fixture::create();
    let item = v
        .transact(|t| {
            let i = t.create_item(secret_item("stripe/acme"))?;
            t.add_field(i, name("value"), SecretBytes::copy_from(b"v"))?;
            Ok(i)
        })
        .unwrap();
    let m = v.item(item).unwrap().clone();
    let created = m.classification_changed_at.unwrap();
    assert_eq!(created, m.created_at);
    assert_eq!((m.exposure.clone(), m.rotate_recommended), (None, false));

    v.transact(|t| t.mark_exposed(item, &[ExposureSource::Transcript], 2))
        .unwrap();
    let first = v.item(item).unwrap().exposure.clone().unwrap();
    v.transact(|t| {
        t.mark_exposed(
            item,
            &[ExposureSource::GitHistory, ExposureSource::Transcript],
            3,
        )
    })
    .unwrap();
    let m = v.item(item).unwrap().clone();
    let x = m.exposure.clone().unwrap();
    assert_eq!(x.since, first.since);
    assert_eq!(
        x.sources,
        [ExposureSource::Transcript, ExposureSource::GitHistory]
    );
    assert_eq!(x.count, 5);
    assert!(m.rotate_recommended);
    assert_eq!(
        v.transact(|t| t.mark_exposed(item, &[], 1))
            .unwrap_err()
            .kind(),
        VaultErrorKind::InvalidRecord
    );

    // An edit that keeps the classification keeps its time.
    v.transact(|t| {
        t.update_item(
            item,
            ItemDetails {
                title: "renamed".into(),
                ..m.details.clone()
            },
        )
    })
    .unwrap();
    assert_eq!(
        v.item(item).unwrap().classification_changed_at,
        Some(created)
    );
    assert_eq!(v.item(item).unwrap().exposure, Some(x.clone()));
    // A change of it is recorded.
    v.transact(|t| {
        t.update_item(
            item,
            ItemDetails {
                classification: Classification::Live,
                ..m.details.clone()
            },
        )
    })
    .unwrap();
    let changed = v.item(item).unwrap().classification_changed_at.unwrap();
    assert!(changed >= created);
    drop(v);
    let mut v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    let m = v.item(item).unwrap().clone();
    assert_eq!(m.classification_changed_at, Some(changed));
    assert_eq!(m.exposure, Some(x));
    v.transact(|t| t.clear_exposure(item)).unwrap();
    let m = v.item(item).unwrap();
    assert_eq!((m.exposure.clone(), m.rotate_recommended), (None, false));
}

/// A login item lists its typed fields with their kinds and its own
/// metadata, and survives a reopen.
#[test]
fn a_login_lists_typed_fields_and_its_metadata() {
    let (f, mut v) = Fixture::create();
    let id = v
        .transact(|t| t.create_login(login("fixture/editor")))
        .unwrap();
    drop(v);
    let v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    let m = v.item(id).unwrap();
    assert_eq!(m.class, ItemClass::Login);
    assert_eq!(
        m.login,
        Some(LoginMeta {
            tier: LoginTier::Dev,
            session_lifetime: 900,
        })
    );
    let kinds: Vec<(String, FieldKind)> = m
        .fields
        .iter()
        .map(|f| (f.name.as_str().to_owned(), f.kind))
        .collect();
    assert_eq!(
        kinds,
        [
            ("adapter_key".to_owned(), FieldKind::AdapterKey),
            ("password".to_owned(), FieldKind::Password),
            ("totp".to_owned(), FieldKind::TotpSeed),
            ("username".to_owned(), FieldKind::Username),
        ]
    );
    assert!(m.fields.iter().all(|f| f.prior_count == 0));
}
