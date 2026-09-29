//! SPEC §15.2 gates 1, 2 (the crypto part) and 3.
//!
//! - Gate 1: any bit flip in a sealed value's nonce, ciphertext or tag, and
//!   any change to its associated data (another row, field, table, item
//!   class, row version, key epoch, schema version or vault), fails with a
//!   value-free error.
//! - Gate 2: a million seals repeat no nonce; the associated data is the
//!   canonical tuple; sealed bytes hold no fixture in any encoding.
//! - Gate 3: out-of-bounds Argon2id parameters are rejected before any
//!   derivation (a spy KDF counts calls); re-wraps use the current
//!   defaults; every wrong secret or damaged envelope gives one generic
//!   error; the commitment rejects a wrong KEK.
//!
//! Argon2id runs at the minimum bounds (64 MiB, t = 2, p = 1), except where
//! a test checks the defaults.
#![allow(clippy::unwrap_used)]

use std::cell::Cell;
use std::collections::HashSet;

use envcloak_core::SecretBytes;
use envcloak_core::crypto::{
    Aad, Argon2id, CryptoError, CryptoErrorKind, Envelope, EnvelopeCtx, FieldTag, ItemClass, Kdf,
    KdfParams, Kek, Keyring, Purpose, Sealed, TableTag, UnlockerId, UnlockerKind, VaultId, Vmk,
    keyed_hash, open, rewrap_vmk, seal, unwrap_vmk, unwrap_vmk_with, wrap_vmk, wrap_vmk_with,
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

/// The encoding, rebuilt here field by field from the documented layout
/// (docs/CRYPTO.md), independently of `Aad::encode`.
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
        (TableTag::Unlockers, 7),
        (TableTag::Backup, 8),
        (TableTag::FileBackup, 9),
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
        (FieldTag::BackupManifest, 9),
        (FieldTag::BackupChunk, 10),
        (FieldTag::FileBackupKey, 11),
        (FieldTag::FileBackupManifest, 12),
        (FieldTag::FileBackupContent, 13),
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
    let pass = SecretBytes::copy_from(by_label(&cs, labels::VAULT_PASSPHRASE).value());
    let env = wrap_min(&Vmk::generate(), &pass, UnlockerKind::Passphrase, &ctx(1));
    det.assert_absent(&env.to_bytes());
    det.assert_absent(format!("{env:?} {kr:?}").as_bytes());
}

// ---------------------------------------------------------------- gate 3

/// Counts derivations, then runs the real Argon2id.
struct SpyKdf(Cell<usize>);

impl SpyKdf {
    fn new() -> Self {
        SpyKdf(Cell::new(0))
    }
    fn calls(&self) -> usize {
        self.0.get()
    }
}

impl Kdf for SpyKdf {
    fn derive(&self, secret: &SecretBytes, params: &KdfParams) -> Result<Kek, CryptoError> {
        self.0.set(self.0.get() + 1);
        Argon2id.derive(secret, params)
    }
}

fn ctx(epoch: u32) -> EnvelopeCtx {
    EnvelopeCtx {
        vault_id: VaultId::generate(),
        unlocker_id: UnlockerId::generate(),
        epoch,
    }
}

fn wrap_min(vmk: &Vmk, secret: &SecretBytes, kind: UnlockerKind, c: &EnvelopeCtx) -> Envelope {
    wrap_vmk_with(vmk, secret, kind, c, &KdfParams::minimum(), &Argon2id).unwrap()
}

/// A value that identifies a VMK without revealing it.
fn fingerprint(vmk: &Vmk) -> [u8; 32] {
    let kr = Keyring::derive(vmk, &VaultId([0; 16]), 0);
    keyed_hash(kr.key(Purpose::Index), "envcloak/v1/test-fingerprint", b"")
}

fn out_of_bounds() -> Vec<(u32, u32, u32)> {
    vec![
        (KdfParams::MIN_M_KIB - 1, 2, 1),
        (8, 2, 1),
        (0, 2, 1),
        (KdfParams::MAX_M_KIB + 1, 2, 1),
        (u32::MAX, 2, 1),
        (KdfParams::MIN_M_KIB, 1, 1),
        (KdfParams::MIN_M_KIB, 0, 1),
        (KdfParams::MIN_M_KIB, 17, 1),
        (KdfParams::MIN_M_KIB, u32::MAX, 1),
        (KdfParams::MIN_M_KIB, 2, 0),
        (KdfParams::MIN_M_KIB, 2, 17),
        (KdfParams::MIN_M_KIB, 2, u32::MAX),
    ]
}

#[test]
fn out_of_bounds_params_are_rejected_before_any_kdf_work() {
    let cs = fixtures();
    let det = Detector::new(&cs);
    let pass = SecretBytes::copy_from(by_label(&cs, labels::VAULT_PASSPHRASE).value());
    let c = ctx(1);
    let vmk = Vmk::generate();
    let spy = SpyKdf::new();

    // Wrapping with out-of-bounds parameters never reaches the KDF.
    for (m_kib, t, p) in out_of_bounds() {
        let params = KdfParams {
            m_kib,
            t,
            p,
            ..KdfParams::minimum()
        };
        let e =
            wrap_vmk_with(&vmk, &pass, UnlockerKind::Passphrase, &c, &params, &spy).unwrap_err();
        assert_value_free(&e, CryptoErrorKind::KdfParams, &det);
    }
    assert_eq!(spy.calls(), 0);

    // Stored parameters are bounded when read: an envelope whose bytes
    // carry them does not parse, so there is nothing to unwrap. (Unwrap's
    // own check is covered by a unit test in envelope.rs.)
    let env = wrap_vmk_with(
        &vmk,
        &pass,
        UnlockerKind::Passphrase,
        &c,
        &KdfParams::minimum(),
        &spy,
    )
    .unwrap();
    assert_eq!(spy.calls(), 1);
    let bytes = env.to_bytes();
    for (m_kib, t, p) in out_of_bounds() {
        let mut b = bytes;
        b[27..31].copy_from_slice(&m_kib.to_be_bytes());
        b[31..35].copy_from_slice(&t.to_be_bytes());
        b[35..39].copy_from_slice(&p.to_be_bytes());
        let e = Envelope::from_bytes(&b).unwrap_err();
        assert_value_free(&e, CryptoErrorKind::KdfParams, &det);
    }

    // Control: in-bounds parameters do reach the KDF, once per unwrap.
    let parsed = Envelope::from_bytes(&bytes).unwrap();
    let got = unwrap_vmk_with(&parsed, &pass, &c, &spy).unwrap();
    assert_eq!(spy.calls(), 2);
    assert_eq!(fingerprint(&got), fingerprint(&vmk));
}

#[test]
fn an_envelope_for_another_unlocker_or_epoch_is_refused_before_kdf_work() {
    let cs = fixtures();
    let det = Detector::new(&cs);
    let pass = SecretBytes::copy_from(by_label(&cs, labels::VAULT_PASSPHRASE).value());
    let c = ctx(2);
    let env = wrap_min(&Vmk::generate(), &pass, UnlockerKind::Passphrase, &c);
    let spy = SpyKdf::new();
    let other_unlocker = EnvelopeCtx {
        unlocker_id: UnlockerId::generate(),
        ..c
    };
    let other_epoch = EnvelopeCtx { epoch: 3, ..c };
    for wrong in [other_unlocker, other_epoch] {
        let e = unwrap_vmk_with(&env, &pass, &wrong, &spy).unwrap_err();
        assert_value_free(&e, CryptoErrorKind::EnvelopeMismatch, &det);
    }
    assert_eq!(spy.calls(), 0);
}

#[test]
fn wrap_and_unwrap_round_trip_for_both_kinds() {
    let cs = fixtures();
    let pass = SecretBytes::copy_from(by_label(&cs, labels::VAULT_PASSPHRASE).value());
    let kit = SecretBytes::copy_from(&[0x5a; 16]);
    let c = ctx(0);
    let vmk = Vmk::generate();
    for (kind, secret) in [
        (UnlockerKind::Passphrase, &pass),
        (UnlockerKind::RecoveryKit, &kit),
    ] {
        let env = wrap_min(&vmk, secret, kind, &c);
        assert_eq!(env.kind(), kind);
        assert_eq!(env.unlocker_id(), c.unlocker_id);
        assert_eq!(env.epoch(), c.epoch);
        assert_eq!(env.version(), Envelope::FORMAT_VERSION);
        let parsed = Envelope::from_bytes(&env.to_bytes()).unwrap();
        assert!(parsed == env);
        let got = unwrap_vmk(&parsed, secret, &c).unwrap();
        assert_eq!(fingerprint(&got), fingerprint(&vmk));
    }
    // Two wraps of the same VMK share no salt, nonce or ciphertext.
    let a = wrap_min(&vmk, &pass, UnlockerKind::Passphrase, &c).to_bytes();
    let b = wrap_min(&vmk, &pass, UnlockerKind::Passphrase, &c).to_bytes();
    assert_ne!(a[39..55], b[39..55], "salt");
    assert_ne!(a[55..79], b[55..79], "nonce");
    assert_ne!(a[111..], b[111..], "ciphertext");
}

/// A wrong passphrase or kit, a damaged envelope and an envelope from
/// another vault all give the same error, with the same text.
#[test]
fn every_wrong_secret_or_damaged_envelope_gives_one_generic_error() {
    let cs = fixtures();
    let det = Detector::new(&cs);
    let pass_value = by_label(&cs, labels::VAULT_PASSPHRASE).value();
    let pass = SecretBytes::copy_from(pass_value);
    let c = ctx(5);
    let env = wrap_min(&Vmk::generate(), &pass, UnlockerKind::Passphrase, &c);
    let bytes = env.to_bytes();

    let mut attempts: Vec<(&str, Envelope, SecretBytes, EnvelopeCtx)> = Vec::new();
    let wrong_secrets: Vec<(&str, SecretBytes)> = vec![
        (
            "wrong passphrase",
            SecretBytes::copy_from(b"not the passphrase at all"),
        ),
        (
            "prefix",
            SecretBytes::copy_from(&pass_value[..pass_value.len() - 1]),
        ),
        (
            "extended",
            SecretBytes::copy_from(&[pass_value, b" "].concat()),
        ),
        ("empty", SecretBytes::copy_from(b"")),
        ("a kit", SecretBytes::copy_from(&[0x5a; 16])),
        (
            "another fixture",
            SecretBytes::copy_from(by_label(&cs, labels::OPENAI_API_KEY).value()),
        ),
    ];
    for (what, s) in wrong_secrets {
        attempts.push((what, env.clone(), s, c));
    }
    // One flipped bit in each region the KDF, commitment or AEAD covers,
    // with the right passphrase. Each damaged envelope must still parse:
    // one that did not would never reach unwrap, and the case would be
    // lost without a trace.
    let regions = [
        ("magic-free kind byte", 5usize),
        ("salt", 39),
        ("salt end", 54),
        ("nonce", 55),
        ("nonce end", 78),
        ("commitment", 79),
        ("commitment end", 110),
        ("ciphertext", 111),
        ("tag", 158),
    ];
    for (what, at) in regions {
        let mut b = bytes;
        b[at] ^= if what.starts_with("magic-free") {
            0x03
        } else {
            0x01
        };
        let e = Envelope::from_bytes(&b)
            .unwrap_or_else(|e| panic!("the envelope with a damaged {what} does not parse: {e}"));
        attempts.push((what, e, SecretBytes::copy_from(pass_value), c));
    }
    // An in-bounds change of the stored parameters: the KDF runs with them,
    // then the commitment fails.
    let mut b = bytes;
    b[34] ^= 1; // t = 2 becomes 3
    attempts.push((
        "kdf params",
        Envelope::from_bytes(&b).unwrap(),
        SecretBytes::copy_from(pass_value),
        c,
    ));
    // The same envelope presented as another vault's.
    let moved = EnvelopeCtx {
        vault_id: VaultId::generate(),
        ..c
    };
    attempts.push((
        "another vault",
        env.clone(),
        SecretBytes::copy_from(pass_value),
        moved,
    ));

    // Six wrong secrets, nine damaged regions, the parameters and the vault.
    assert_eq!(attempts.len(), 17);
    let mut messages = HashSet::new();
    for (what, e, s, ctx) in &attempts {
        let err = unwrap_vmk(e, s, ctx).map(|_| ()).unwrap_err();
        assert_eq!(err.kind(), CryptoErrorKind::Unlock, "{what}");
        assert_value_free(&err, CryptoErrorKind::Unlock, &det);
        messages.insert(err.to_string());
    }
    assert_eq!(messages.len(), 1);

    // The flipped kind byte (passphrase 1 to kit 2) parses and still fails
    // generically; an unknown kind does not parse.
    let mut b = bytes;
    b[5] = 9;
    assert_eq!(
        Envelope::from_bytes(&b).unwrap_err().kind(),
        CryptoErrorKind::EnvelopeFormat
    );

    // Control: the right passphrase opens it.
    unwrap_vmk(&env, &pass, &c).unwrap();
}

#[test]
fn the_commitment_rejects_a_wrong_kek_even_when_nothing_else_changed() {
    // Only the commitment differs, and the passphrase is right: the AEAD
    // would accept this envelope, so only the commitment check refuses it.
    let pass = SecretBytes::copy_from(b"a passphrase that is right");
    let c = ctx(1);
    let env = wrap_min(&Vmk::generate(), &pass, UnlockerKind::Passphrase, &c);
    unwrap_vmk(&env, &pass, &c).unwrap();
    for bit in [0usize, 7, 100, 255] {
        let mut b = env.to_bytes();
        b[79 + bit / 8] ^= 1 << (bit % 8);
        let e = unwrap_vmk(&Envelope::from_bytes(&b).unwrap(), &pass, &c).unwrap_err();
        assert_eq!(e.kind(), CryptoErrorKind::Unlock);
    }
}

#[test]
fn envelope_parsing_rejects_malformed_bytes() {
    let pass = SecretBytes::copy_from(b"a passphrase for parsing");
    let env = wrap_min(&Vmk::generate(), &pass, UnlockerKind::RecoveryKit, &ctx(1));
    let bytes = env.to_bytes();
    assert_eq!(bytes.len(), Envelope::LEN);
    let format = CryptoErrorKind::EnvelopeFormat;
    let kind = |b: &[u8]| Envelope::from_bytes(b).unwrap_err().kind();
    assert_eq!(kind(&[]), format);
    assert_eq!(kind(&bytes[..Envelope::LEN - 1]), format);
    assert_eq!(kind(&[&bytes[..], &[0]].concat()), format);
    for (at, value) in [
        (0usize, b'X'),
        (3, 0),
        (4, 0),
        (4, 2),
        (5, 0),
        (5, 3),
        (26, 0),
        (26, 2),
    ] {
        let mut b = bytes;
        b[at] = value;
        assert_eq!(kind(&b), format, "byte {at} = {value}");
    }
    assert!(Envelope::from_bytes(&bytes).unwrap() == env);
    assert_eq!(&bytes[..6], b"ECEV\x01\x02");
}

#[test]
fn wrap_vmk_uses_the_current_defaults() {
    let pass = SecretBytes::copy_from(b"a passphrase for the defaults");
    let c = ctx(1);
    let vmk = Vmk::generate();
    let env = wrap_vmk(&vmk, &pass, UnlockerKind::Passphrase, &c).unwrap();
    let d = KdfParams::current_defaults();
    let k = env.kdf();
    assert_eq!((k.m_kib, k.t, k.p), (d.m_kib, d.t, d.p));
    assert_eq!((k.m_kib, k.t, k.p), (256 * 1024, 3, 4));
    assert_ne!(k.salt, d.salt);
    assert_eq!(
        fingerprint(&unwrap_vmk(&env, &pass, &c).unwrap()),
        fingerprint(&vmk)
    );
}

#[test]
fn a_rewrap_uses_the_current_defaults_not_the_stored_params() {
    let old = SecretBytes::copy_from(b"the old passphrase here");
    let new = SecretBytes::copy_from(b"the new passphrase here");
    let c = ctx(6);
    let vmk = Vmk::generate();
    let env = wrap_min(&vmk, &old, UnlockerKind::Passphrase, &c);
    assert_eq!(env.kdf().m_kib, KdfParams::MIN_M_KIB);

    // The old secret is required.
    let e = rewrap_vmk(&env, &new, &new, &c).unwrap_err();
    assert_eq!(e.kind(), CryptoErrorKind::Unlock);

    let re = rewrap_vmk(&env, &old, &new, &c).unwrap();
    let k = re.kdf();
    assert_eq!(
        (k.m_kib, k.t, k.p),
        (
            KdfParams::DEFAULT_M_KIB,
            KdfParams::DEFAULT_T,
            KdfParams::DEFAULT_P
        )
    );
    assert_ne!(k.salt, env.kdf().salt);
    assert_eq!(re.kind(), env.kind());
    assert_eq!(re.unlocker_id(), env.unlocker_id());
    assert_eq!(
        fingerprint(&unwrap_vmk(&re, &new, &c).unwrap()),
        fingerprint(&vmk)
    );
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
        (
            CryptoErrorKind::KdfParams,
            "key derivation parameters are out of bounds",
        ),
        (CryptoErrorKind::Kdf, "key derivation failed"),
        (
            CryptoErrorKind::EnvelopeFormat,
            "unlocker envelope is malformed or has an unsupported format",
        ),
        (
            CryptoErrorKind::EnvelopeMismatch,
            "unlocker envelope belongs to another unlocker or key epoch",
        ),
        (
            CryptoErrorKind::Unlock,
            "wrong passphrase or Recovery Kit, or the unlocker envelope is damaged",
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
static_assertions::assert_not_impl_any!(
    Kek: Clone,
    Copy,
    std::fmt::Display,
    serde::Serialize
);
