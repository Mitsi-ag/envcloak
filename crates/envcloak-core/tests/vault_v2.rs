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
    // The control: the read-only vault does serve what opens, so the sweep
    // below reads values, and the secret's own is among them.
    assert!(
        v.read_value(s.fields[0].id)
            .unwrap()
            .ct_eq(b"a secret value")
    );
    let mut read = 0;
    for item in v.items() {
        for field in &item.fields {
            if let Ok(got) = v.read_value(field.id) {
                read += 1;
                assert!(!got.ct_eq(PASSWORD), "{}#{}", item.slug, field.name);
            }
        }
    }
    assert!(read >= 1, "the sweep read no value");
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

/// The value keys of one class list that class's fields and no other's
/// (M2-11: what `scan.match` and the import methods look a value up
/// among, so a card's value or a login's is never compared, R-M2-34): a
/// value a secret and a card both hold is listed once for each class, by
/// its own field, under the key [`Vault::value_key`] gives it; a login's
/// fields are listed for the login class alone, and its password's key is
/// not the one the same text has as a secret's value (its own domain).
///
/// Mutation: the class filter dropped (the secret list holds the card's
/// field and the login's).
#[test]
fn value_keys_of_a_class_list_that_class_alone() {
    let (_f, mut v) = Fixture::create();
    let same: &[u8] = b"one value a secret and a card hold";
    let (secret_field, card_field, login_id) = v
        .transact(|t| {
            let s = t.create_item(secret_item("same/secret"))?;
            let sf = t.add_field(s, name("value"), SecretBytes::copy_from(same))?;
            let c = t.create_item(envcloak_core::vault::NewItem {
                class: ItemClass::Card,
                ..secret_item("same/card")
            })?;
            let cf = t.add_field(c, name("value"), SecretBytes::copy_from(same))?;
            let l = t.create_login(login("fixture/editor"))?;
            Ok((sf, cf, l))
        })
        .unwrap();
    let key = v.value_key(&SecretBytes::copy_from(same));
    assert_eq!(v.value_keys_of(ItemClass::Secret), [(secret_field, key)]);
    assert_eq!(v.value_keys_of(ItemClass::Card), [(card_field, key)]);
    let logins = v.value_keys_of(ItemClass::Login);
    let fields: Vec<_> = v
        .item(login_id)
        .unwrap()
        .fields
        .iter()
        .map(|f| f.id)
        .collect();
    assert_eq!(logins.len(), fields.len());
    assert!(logins.iter().all(|(f, _)| fields.contains(f)));
    let as_secret = v.value_key(&SecretBytes::copy_from(PASSWORD));
    assert!(logins.iter().all(|(_, k)| *k != as_secret));
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

/// Item record v2: an exposure only grows (its first mark's time kept, the
/// kinds joined, the counts summed) and sets the rotation flag; clearing it
/// clears both. The classification's last change is recorded at creation
/// and at every change, and only then. Both survive a reopen.
///
/// Each transaction runs at a time of its own (the vault's test clock), so
/// every time asserted is the one transaction's that should have set it
/// and no other's: the first mark's, not the second's; the creation's
/// after an edit that keeps the classification; the change's after one
/// that changes it. Mutations checked: `since` set at every mark (this
/// fails: it reads the second mark's time); the classification's time
/// left alone when it changes, and moved by an edit that keeps it (each
/// fails here).
#[test]
fn exposure_and_the_classification_time_are_kept_by_the_vault() {
    // The transactions' times, each a different second.
    const CREATED: u64 = 1_800_000_000;
    const FIRST_MARK: u64 = CREATED + 100;
    const SECOND_MARK: u64 = CREATED + 200;
    const RENAMED: u64 = CREATED + 300;
    const RECLASSIFIED: u64 = CREATED + 400;
    const CLEARED: u64 = CREATED + 500;

    let (f, mut v) = Fixture::create();
    let item = v
        .transact_at_for_testing(CREATED, |t| {
            let i = t.create_item(secret_item("stripe/acme"))?;
            t.add_field(i, name("value"), SecretBytes::copy_from(b"v"))?;
            Ok(i)
        })
        .unwrap();
    let m = v.item(item).unwrap().clone();
    assert_eq!(m.created_at, CREATED);
    assert_eq!(m.classification_changed_at, Some(CREATED));
    assert_eq!((m.exposure.clone(), m.rotate_recommended), (None, false));

    v.transact_at_for_testing(FIRST_MARK, |t| {
        t.mark_exposed(item, &[ExposureSource::Transcript], 2)
    })
    .unwrap();
    let first = v.item(item).unwrap().clone();
    assert_eq!(first.exposure.clone().unwrap().since, FIRST_MARK);
    assert_eq!(first.updated_at, FIRST_MARK);
    v.transact_at_for_testing(SECOND_MARK, |t| {
        t.mark_exposed(
            item,
            &[ExposureSource::GitHistory, ExposureSource::Transcript],
            3,
        )
    })
    .unwrap();
    let m = v.item(item).unwrap().clone();
    // The second mark wrote the row (its time is the row's), and kept the
    // first mark's time as the exposure's.
    assert_eq!(m.updated_at, SECOND_MARK);
    let x = m.exposure.clone().unwrap();
    assert_eq!(x.since, FIRST_MARK, "the first mark's time is kept");
    assert_eq!(
        x.sources,
        [ExposureSource::Transcript, ExposureSource::GitHistory]
    );
    assert_eq!(x.count, 5);
    assert!(m.rotate_recommended);
    assert_eq!(m.classification_changed_at, Some(CREATED));
    assert_eq!(
        v.transact_at_for_testing(SECOND_MARK + 1, |t| t.mark_exposed(item, &[], 1))
            .unwrap_err()
            .kind(),
        VaultErrorKind::InvalidRecord
    );

    // An edit that keeps the classification keeps its time.
    v.transact_at_for_testing(RENAMED, |t| {
        t.update_item(
            item,
            ItemDetails {
                title: "renamed".into(),
                ..m.details.clone()
            },
        )
    })
    .unwrap();
    let renamed = v.item(item).unwrap().clone();
    assert_eq!(renamed.updated_at, RENAMED);
    assert_eq!(renamed.classification_changed_at, Some(CREATED));
    assert_eq!(renamed.exposure, Some(x.clone()));
    // A change of it is recorded, at the time of the change.
    assert_ne!(m.details.classification, Classification::Live);
    v.transact_at_for_testing(RECLASSIFIED, |t| {
        t.update_item(
            item,
            ItemDetails {
                classification: Classification::Live,
                ..renamed.details.clone()
            },
        )
    })
    .unwrap();
    assert_eq!(
        v.item(item).unwrap().classification_changed_at,
        Some(RECLASSIFIED)
    );
    drop(v);
    let mut v = f.unlock();
    assert_eq!(v.integrity(), Integrity::Ok);
    let m = v.item(item).unwrap().clone();
    assert_eq!(m.classification_changed_at, Some(RECLASSIFIED));
    assert_eq!(m.exposure, Some(x));
    v.transact_at_for_testing(CLEARED, |t| t.clear_exposure(item))
        .unwrap();
    let m = v.item(item).unwrap();
    assert_eq!((m.exposure.clone(), m.rotate_recommended), (None, false));
    assert_eq!(m.updated_at, CLEARED);
    assert_eq!(m.classification_changed_at, Some(RECLASSIFIED));
}

/// A mark covers the values an item held at its time (M2-11, Codex
/// review): a second mark keeps the first mark's time while the item holds
/// no value set after it, and restarts it once the item holds one (a field
/// replaced since the mark, whose new value may be the one found), so the
/// mark covers every value again. [`ItemMeta::exposure_covers`] and
/// [`ItemMeta::exposure_replaced_but`] read the same rule: a value set in
/// the mark's own second counts as covered, never as replaced.
///
/// Mutations: the first mark's time kept whatever the item holds (the
/// third mark keeps it); a value set in the mark's second counted as
/// replaced (`exposure_replaced_but` says true at the end).
#[test]
fn a_mark_restarts_when_the_item_holds_a_value_set_after_it() {
    const CREATED: u64 = 1_800_000_000;
    const FIRST_MARK: u64 = CREATED + 100;
    const SECOND_MARK: u64 = CREATED + 150;
    const SET_A: u64 = CREATED + 200;
    const THIRD_MARK: u64 = CREATED + 300;

    let (f, mut v) = Fixture::create();
    let (item, a, b) = v
        .transact_at_for_testing(CREATED, |t| {
            let i = t.create_item(secret_item("two/fields"))?;
            let a = t.add_field(i, name("a"), SecretBytes::copy_from(b"value of a"))?;
            let b = t.add_field(i, name("b"), SecretBytes::copy_from(b"value of b"))?;
            Ok((i, a, b))
        })
        .unwrap();
    assert!(!v.item(item).unwrap().exposure_covers());
    let mark = |v: &mut envcloak_core::vault::Vault, at, source| {
        v.transact_at_for_testing(at, |t| t.mark_exposed(item, &[source], 1))
            .unwrap();
        v.item(item).unwrap().clone()
    };
    let m = mark(&mut v, FIRST_MARK, ExposureSource::Transcript);
    assert_eq!(m.exposure.as_ref().unwrap().since, FIRST_MARK);
    assert!(m.exposure_covers());
    assert!(!m.exposure_replaced_but(a) && !m.exposure_replaced_but(b));
    let m = mark(&mut v, SECOND_MARK, ExposureSource::GitHistory);
    assert_eq!(m.exposure.as_ref().unwrap().since, FIRST_MARK);
    // `a` replaced after the mark: the mark no longer covers every value,
    // and replacing `b` too would leave none it covers.
    v.transact_at_for_testing(SET_A, |t| {
        t.set_value(a, SecretBytes::copy_from(b"new value of a"))
    })
    .unwrap();
    let m = v.item(item).unwrap().clone();
    assert!(!m.exposure_covers());
    assert!(m.exposure_replaced_but(b) && !m.exposure_replaced_but(a));
    // A mark now restarts the mark's time, the kinds and counts kept.
    let m = mark(&mut v, THIRD_MARK, ExposureSource::Transcript);
    let x = m.exposure.clone().unwrap();
    assert_eq!(x.since, THIRD_MARK);
    assert_eq!(
        x.sources,
        [ExposureSource::Transcript, ExposureSource::GitHistory]
    );
    assert_eq!(x.count, 3);
    assert!(m.exposure_covers());
    assert!(!m.exposure_replaced_but(b) && !m.exposure_replaced_but(a));
    // A value set in the mark's own second is covered, not replaced.
    v.transact_at_for_testing(THIRD_MARK, |t| {
        t.set_value(b, SecretBytes::copy_from(b"new value of b"))
    })
    .unwrap();
    let m = v.item(item).unwrap().clone();
    assert!(m.exposure_covers());
    assert!(!m.exposure_replaced_but(a));
    drop(v);
    let v = f.unlock();
    assert_eq!(v.item(item).unwrap().exposure, Some(x));
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
