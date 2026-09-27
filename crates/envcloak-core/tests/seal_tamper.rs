//! SPEC §15.2 gates 1 and 2 (the crypto part).
//!
//! - Gate 1: any bit flip in a sealed value's nonce, ciphertext or tag, and
//!   any change to its associated data (another row, field, table, item
//!   class, row version, key epoch, schema version or vault), fails with a
//!   value-free error.
//! - Gate 2: a million seals repeat no nonce; the associated data is the
//!   canonical tuple; sealed bytes hold no fixture in any encoding.
#![allow(clippy::unwrap_used)]

use std::collections::HashSet;

use envcloak_core::crypto::{
    Aad, CryptoError, CryptoErrorKind, FieldTag, ItemClass, Keyring, Purpose, Sealed, TableTag,
    VaultId, Vmk, open, seal,
};
use envcloak_testkit::{Canary, Detector, by_label, canaries, fresh_seed, labels};

fn fixtures() -> Vec<Canary> {
    canaries(fresh_seed())
}

fn keyring(epoch: u32) -> Keyring {
    Keyring::derive(&Vmk::generate(), &VaultId::generate(), epoch)
}

fn aad_for(kr: &Keyring) -> Aad {
    Aad {
        vault_id: kr.vault_id(),
        schema_version: 1,
        key_epoch: kr.epoch(),
        table: TableTag::Fields,
        row_id: [0x11; 16],
        field: FieldTag::FieldValue,
        item_class: ItemClass::Secret,
        row_version: 5,
    }
}

/// Checks that `e` is `kind` and that neither its `Display` nor its `Debug`
/// output holds any fixture.
fn assert_value_free(e: &CryptoError, kind: CryptoErrorKind, det: &Detector) {
    assert_eq!(e.kind(), kind);
    let shown = format!("{e} {e:?} {e:#?}");
    det.assert_absent(shown.as_bytes());
}

// ---------------------------------------------------------------- gate 1

#[test]
fn every_bit_flip_in_nonce_ciphertext_or_tag_fails() {
    let cs = fixtures();
    let det = Detector::new(&cs);
    let kr = keyring(1);
    let k = kr.key(Purpose::Data);
    let aad = aad_for(&kr);
    for c in &cs {
        let sealed = seal(k, &aad, c.value()).unwrap();
        assert!(open(k, &aad, &sealed).unwrap().ct_eq(c.value()));
        let bytes = sealed.to_bytes();
        assert_eq!(bytes.len(), Sealed::OVERHEAD + c.value().len());
        for bit in 0..bytes.len() * 8 {
            let mut t = bytes.clone();
            t[bit / 8] ^= 1 << (bit % 8);
            let e = open(k, &aad, &Sealed::from_bytes(&t).unwrap()).unwrap_err();
            assert_value_free(&e, CryptoErrorKind::Open, &det);
        }
    }
}

#[test]
fn truncated_or_extended_ciphertexts_fail() {
    let cs = fixtures();
    let det = Detector::new(&cs);
    let kr = keyring(1);
    let k = kr.key(Purpose::Data);
    let aad = aad_for(&kr);
    let v = by_label(&cs, labels::GITHUB_TOKEN).value();
    let bytes = seal(k, &aad, v).unwrap().to_bytes();
    for cut in 1..=bytes.len() {
        let short = &bytes[..bytes.len() - cut];
        match Sealed::from_bytes(short) {
            Ok(s) => {
                assert_value_free(&open(k, &aad, &s).unwrap_err(), CryptoErrorKind::Open, &det)
            }
            Err(e) => assert_value_free(&e, CryptoErrorKind::Malformed, &det),
        }
    }
    let mut long = bytes.clone();
    long.push(0);
    let e = open(k, &aad, &Sealed::from_bytes(&long).unwrap()).unwrap_err();
    assert_value_free(&e, CryptoErrorKind::Open, &det);
    // A ciphertext shorter than a tag, built directly.
    let s = Sealed {
        nonce: [0; 24],
        ciphertext: vec![0; 15],
    };
    assert_value_free(
        &open(k, &aad, &s).unwrap_err(),
        CryptoErrorKind::Malformed,
        &det,
    );
}

/// Every component of the associated data, changed on its own.
fn aad_variants(a: &Aad) -> Vec<(&'static str, Aad)> {
    let mut vault = a.vault_id;
    vault.0[15] ^= 1;
    let mut row = a.row_id;
    row[0] ^= 0x80;
    vec![
        (
            "vault_id",
            Aad {
                vault_id: vault,
                ..*a
            },
        ),
        (
            "schema_version",
            Aad {
                schema_version: a.schema_version + 1,
                ..*a
            },
        ),
        (
            "key_epoch",
            Aad {
                key_epoch: a.key_epoch + 1,
                ..*a
            },
        ),
        (
            "table",
            Aad {
                table: TableTag::Items,
                ..*a
            },
        ),
        ("row_id", Aad { row_id: row, ..*a }),
        (
            "field",
            Aad {
                field: FieldTag::FieldPrior,
                ..*a
            },
        ),
        (
            "item_class",
            Aad {
                item_class: ItemClass::Card,
                ..*a
            },
        ),
        (
            "row_version",
            Aad {
                row_version: a.row_version + 1,
                ..*a
            },
        ),
        (
            "row_version rollback",
            Aad {
                row_version: a.row_version - 1,
                ..*a
            },
        ),
    ]
}

#[test]
fn changing_any_part_of_the_associated_data_fails() {
    let cs = fixtures();
    let det = Detector::new(&cs);
    let kr = keyring(1);
    let k = kr.key(Purpose::Data);
    let aad = aad_for(&kr);
    let v = by_label(&cs, labels::DATABASE_URL).value();
    let sealed = seal(k, &aad, v).unwrap();
    for (what, other) in aad_variants(&aad) {
        assert_ne!(other.encode(), aad.encode(), "{what}");
        let e = open(k, &other, &sealed).unwrap_err();
        assert_value_free(&e, CryptoErrorKind::Open, &det);
    }
    assert!(open(k, &aad, &sealed).unwrap().ct_eq(v));
}

#[test]
fn ciphertexts_swapped_between_rows_fields_tables_or_classes_fail() {
    let cs = fixtures();
    let det = Detector::new(&cs);
    let kr = keyring(1);
    let k = kr.key(Purpose::Data);
    let a = aad_for(&kr);
    let places = [
        a,
        Aad {
            row_id: [0x22; 16],
            ..a
        },
        Aad {
            field: FieldTag::FieldName,
            ..a
        },
        Aad {
            table: TableTag::Projects,
            field: FieldTag::Project,
            item_class: ItemClass::None,
            ..a
        },
        Aad {
            item_class: ItemClass::IssuerCredential,
            ..a
        },
        Aad {
            row_id: [0x33; 16],
            item_class: ItemClass::Card,
            ..a
        },
    ];
    let values: Vec<&[u8]> = cs.iter().map(Canary::value).collect();
    let sealed: Vec<Sealed> = places
        .iter()
        .zip(values.iter().cycle())
        .map(|(aad, v)| seal(k, aad, v).unwrap())
        .collect();
    for (i, from) in sealed.iter().enumerate() {
        for (j, place) in places.iter().enumerate() {
            let got = open(k, place, from);
            if i == j {
                assert!(got.unwrap().ct_eq(values[i % values.len()]));
            } else {
                assert_value_free(&got.unwrap_err(), CryptoErrorKind::Open, &det);
            }
        }
    }
}

#[test]
fn another_purpose_epoch_or_vault_key_fails() {
    let cs = fixtures();
    let det = Detector::new(&cs);
    let vmk = Vmk::generate();
    let vault = VaultId::generate();
    let kr = Keyring::derive(&vmk, &vault, 3);
    let aad = aad_for(&kr);
    let v = by_label(&cs, labels::STRIPE_SECRET_KEY).value();
    let sealed = seal(kr.key(Purpose::Data), &aad, v).unwrap();

    for p in Purpose::ALL.into_iter().filter(|p| *p != Purpose::Data) {
        let e = open(kr.key(p), &aad, &sealed).unwrap_err();
        assert_value_free(&e, CryptoErrorKind::Open, &det);
    }
    // The same VMK in another epoch or vault gives other subkeys.
    let next_epoch = Keyring::derive(&vmk, &vault, 4);
    let other_vault = Keyring::derive(&vmk, &VaultId::generate(), 3);
    for kr2 in [&next_epoch, &other_vault] {
        let e = open(kr2.key(Purpose::Data), &aad, &sealed).unwrap_err();
        assert_value_free(&e, CryptoErrorKind::Open, &det);
    }
    // The same derivation inputs give the same subkeys.
    let again = Keyring::derive(&vmk, &vault, 3);
    assert!(
        open(again.key(Purpose::Data), &aad, &sealed)
            .unwrap()
            .ct_eq(v)
    );
}

// ---------------------------------------------------------------- gate 2

#[test]
fn a_million_seals_repeat_no_nonce() {
    const SEALS: usize = 1_000_000;
    let kr = keyring(1);
    let k = kr.key(Purpose::Data);
    let aad = aad_for(&kr);
    let mut nonces: HashSet<[u8; 24]> = HashSet::with_capacity(SEALS);
    for _ in 0..SEALS {
        let s = seal(k, &aad, b"same plaintext every time").unwrap();
        assert!(nonces.insert(s.nonce), "a nonce repeated");
    }
    assert_eq!(nonces.len(), SEALS);
}

#[test]
fn the_same_plaintext_seals_differently_each_time() {
    let kr = keyring(1);
    let k = kr.key(Purpose::Data);
    let aad = aad_for(&kr);
    let a = seal(k, &aad, b"plaintext").unwrap();
    let b = seal(k, &aad, b"plaintext").unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);
}

/// The encoding, rebuilt here field by field from the documented layout,
/// independently of `Aad::encode`.
fn canonical(a: &Aad) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend(a.vault_id.0);
    v.extend(a.schema_version.to_be_bytes());
    v.extend(a.key_epoch.to_be_bytes());
    v.extend((a.table as u16).to_be_bytes());
    v.extend(a.row_id);
    v.extend((a.field as u16).to_be_bytes());
    v.extend((a.item_class as u16).to_be_bytes());
    v.extend(a.row_version.to_be_bytes());
    v
}

#[test]
fn the_associated_data_is_the_canonical_tuple() {
    let a = Aad {
        vault_id: VaultId(*b"0123456789abcdef"),
        schema_version: 0x0102,
        key_epoch: 0x0304_0506,
        table: TableTag::Audit,
        row_id: *b"ROW-ID-SIXTEEN-B",
        field: FieldTag::AuditEntry,
        item_class: ItemClass::IssuerCredential,
        row_version: 0x0708_090a_0b0c_0d0e,
    };
    assert_eq!(Aad::LEN, 53);
    assert_eq!(a.encode().to_vec(), canonical(&a));

    // Each component changes only its own bytes, at its documented offset.
    let ranges = [
        ("vault_id", 1..17),
        ("schema_version", 17..19),
        ("key_epoch", 19..23),
        ("table", 23..25),
        ("row_id", 25..41),
        ("field", 41..43),
        ("item_class", 43..45),
        ("row_version", 45..53),
    ];
    let base = a.encode();
    for (name, other) in aad_variants(&a) {
        let enc = other.encode();
        assert_eq!(enc.to_vec(), canonical(&other), "{name}");
        let range = ranges
            .iter()
            .find(|(n, _)| name.starts_with(n))
            .map(|(_, r)| r.clone())
            .unwrap();
        for i in 0..Aad::LEN {
            if !range.contains(&i) {
                assert_eq!(enc[i], base[i], "{name} changed byte {i}");
            }
        }
        assert_ne!(enc[range.clone()], base[range], "{name}");
    }

    // The tag numbers are part of the format.
    let tables = [
        (TableTag::Header, 1),
        (TableTag::Items, 2),
        (TableTag::Fields, 3),
        (TableTag::Projects, 4),
        (TableTag::Policies, 5),
        (TableTag::Audit, 6),
    ];
    for (t, n) in tables {
        assert_eq!(t as u16, n);
    }
    let fields = [
        (FieldTag::Header, 1),
        (FieldTag::ItemMeta, 2),
        (FieldTag::FieldName, 3),
        (FieldTag::FieldValue, 4),
        (FieldTag::FieldPrior, 5),
        (FieldTag::Project, 6),
        (FieldTag::Policy, 7),
        (FieldTag::AuditEntry, 8),
    ];
    for (f, n) in fields {
        assert_eq!(f as u16, n);
    }
    let classes = [
        (ItemClass::None, 0),
        (ItemClass::Secret, 1),
        (ItemClass::Card, 2),
        (ItemClass::IssuerCredential, 3),
    ];
    for (c, n) in classes {
        assert_eq!(c as u16, n);
    }
}

#[test]
fn sealed_bytes_hold_no_fixture() {
    let cs = fixtures();
    let det = Detector::new(&cs);
    let kr = keyring(1);
    let aad = aad_for(&kr);
    let mut all = Vec::new();
    for c in &cs {
        for p in [Purpose::Data, Purpose::Header, Purpose::Card] {
            all.extend(seal(kr.key(p), &aad, c.value()).unwrap().to_bytes());
        }
    }
    det.assert_absent(&all);
    det.assert_absent(format!("{kr:?}").as_bytes());
}

// ---------------------------------------------------------------- errors

#[test]
fn error_display_strings_are_enumerated() {
    let expected = [
        (CryptoErrorKind::Seal, "encryption failed"),
        (
            CryptoErrorKind::Open,
            "decryption failed: the data is damaged or belongs elsewhere",
        ),
        (CryptoErrorKind::Malformed, "sealed data is malformed"),
        (
            CryptoErrorKind::Random,
            "the system random number generator failed",
        ),
    ];
    assert_eq!(CryptoErrorKind::ALL.len(), expected.len());
    for (kind, text) in expected {
        assert!(CryptoErrorKind::ALL.contains(&kind));
        assert_eq!(CryptoError::from(kind).to_string(), text);
    }
}

#[test]
fn key_types_print_no_key_material() {
    let kr = keyring(9);
    assert_eq!(format!("{:?}", kr.key(Purpose::Audit)), "SubKey(audit, ..)");
    assert!(format!("{kr:?}").starts_with("Keyring { vault_id: VaultId("));
    assert!(format!("{kr:?}").ends_with("epoch: 9, .. }"));
    assert_eq!(format!("{:?}", Vmk::generate()), "Vmk(..)");
}

static_assertions::assert_not_impl_any!(
    Vmk: Clone,
    Copy,
    std::fmt::Display,
    serde::Serialize
);
static_assertions::assert_not_impl_any!(
    Keyring: Clone,
    Copy,
    std::fmt::Display,
    serde::Serialize
);
static_assertions::assert_not_impl_any!(
    envcloak_core::crypto::SubKey: Clone,
    Copy,
    std::fmt::Display,
    serde::Serialize
);
