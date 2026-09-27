//! Known-answer tests.
//!
//! 1. The standards the vault relies on, against the pinned crates with the
//!    features this workspace builds them with: XChaCha20-Poly1305
//!    (draft-irtf-cfrg-xchacha), HKDF-SHA256 (RFC 5869), Argon2id (RFC 9106
//!    and the reference implementation's test at EnvCloak's minimum
//!    bounds) and BLAKE3 (its published test vectors).
//! 2. EnvCloak's own formats (docs/CRYPTO.md), through the public API,
//!    against vectors that scripts/crypto-kat-vectors.py computes with
//!    independent implementations (OpenSSL's Argon2id, pycryptodome's
//!    XChaCha20-Poly1305, Python's HMAC and a from-the-spec BLAKE3): the
//!    associated data encoding, subkey derivation and keyed hashing for
//!    every purpose, opening a value sealed elsewhere, and unwrapping an
//!    envelope built elsewhere.
#![allow(clippy::unwrap_used)]

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use envcloak_core::SecretBytes;
use envcloak_core::crypto::{
    Aad, CryptoErrorKind, Envelope, EnvelopeCtx, FieldTag, ItemClass, Keyring, Purpose, Sealed,
    TableTag, UnlockerId, UnlockerKind, VaultId, keyed_hash, open, unwrap_vmk,
};
use hkdf::Hkdf;
use sha2::Sha256;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(hex: &str) -> [u8; N] {
    unhex(hex).try_into().unwrap()
}

fn range<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start + i as u8)
}

// ------------------------------------------------------------ standards

/// draft-irtf-cfrg-xchacha-03, appendix A.3.1.
#[test]
fn xchacha20poly1305_matches_the_draft() {
    let key: [u8; 32] = range(0x80);
    let nonce: [u8; 24] = range(0x40);
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip \
for the future, sunscreen would be it.";
    let ct = unhex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
         731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
         2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
         21f9664c97637da9768812f615c68b13b52e",
    );
    let tag = unhex("c0875924c1c7987947deafd8780acf49");

    let cipher = XChaCha20Poly1305::new(&key.into());
    let mut out = vec![0u8; pt.len()];
    let got_tag = cipher
        .encrypt_inout_detached(
            &XNonce::from(nonce),
            &aad,
            InOutBuf::new(pt, &mut out).unwrap(),
        )
        .unwrap();
    assert_eq!(out, ct);
    assert_eq!(got_tag.to_vec(), tag);

    let mut back = vec![0u8; ct.len()];
    cipher
        .decrypt_inout_detached(
            &XNonce::from(nonce),
            &aad,
            InOutBuf::new(&ct, &mut back).unwrap(),
            &Tag::try_from(&tag[..]).unwrap(),
        )
        .unwrap();
    assert_eq!(back, pt);
}

/// RFC 5869 appendix A, test cases 1 to 3.
#[test]
fn hkdf_sha256_matches_rfc5869() {
    struct Case {
        ikm: Vec<u8>,
        salt: Option<Vec<u8>>,
        info: Vec<u8>,
        prk: &'static str,
        okm: &'static str,
    }
    let cases = [
        Case {
            ikm: vec![0x0b; 22],
            salt: Some((0x00..=0x0c).collect()),
            info: (0xf0..=0xf9).collect(),
            prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
                  34007208d5b887185865",
        },
        Case {
            ikm: (0x00..=0x4f).collect(),
            salt: Some((0x60..=0xaf).collect()),
            info: (0xb0..=0xff).collect(),
            prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c
                  59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71
                  cc30c58179ec3e87c14c01d5c1f3434f1d87",
        },
        Case {
            ikm: vec![0x0b; 22],
            salt: None,
            info: vec![],
            prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d
                  9d201395faa4b61a96c8",
        },
    ];
    for c in cases {
        let (prk, hk) = Hkdf::<Sha256>::extract(c.salt.as_deref(), &c.ikm);
        assert_eq!(prk.to_vec(), unhex(c.prk));
        let want = unhex(c.okm);
        let mut okm = vec![0u8; want.len()];
        hk.expand(&c.info, &mut okm).unwrap();
        assert_eq!(okm, want);
    }
}

/// RFC 9106 section 5.3 (Argon2id, version 0x13, with a secret and
/// associated data).
#[test]
fn argon2id_matches_rfc9106() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[0x04; 12]).unwrap())
        .output_len(32)
        .build()
        .unwrap();
    let secret = [0x03; 8];
    let a = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    a.hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
        .unwrap();
    assert_eq!(
        out,
        arr("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
}

/// The reference implementation's Argon2id test at m = 64 MiB, t = 2,
/// p = 1 (phc-winner-argon2 src/test.c), EnvCloak's minimum bounds:
/// `$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc`.
#[test]
fn argon2id_matches_the_reference_at_the_minimum_bounds() {
    let params = argon2::Params::new(65536, 2, 1, Some(32)).unwrap();
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(b"password", b"somesalt", &mut out)
        .unwrap();
    assert_eq!(
        out,
        arr("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")
    );
}

/// BLAKE3 test_vectors.json (key "whats the Elvish word for friend",
/// input bytes i % 251), first 32 bytes of each output; the three longest
/// inputs, whose trees are deeper than the published ones checked here,
/// come from the specification-based implementation in the script.
#[test]
fn blake3_matches_its_test_vectors() {
    let key = b"whats the Elvish word for friend";
    let input = |n: usize| (0..n).map(|i| (i % 251) as u8).collect::<Vec<u8>>();
    let published = [
        (
            0,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
        ),
        (
            1,
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
        ),
        (
            1025,
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
            "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69",
        ),
    ];
    for (n, hash, keyed) in published {
        assert_eq!(blake3::hash(&input(n)).as_bytes(), &arr::<32>(hash));
        assert_eq!(
            blake3::keyed_hash(key, &input(n)).as_bytes(),
            &arr::<32>(keyed)
        );
    }
    let deeper = [
        (
            2049,
            "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5",
        ),
        (
            8193,
            "954a2a75420c8d6547e3ba5b98d963e6fa6491addc8c023189cc519821b4a1f5",
        ),
        (
            31744,
            "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a419",
        ),
    ];
    for (n, keyed) in deeper {
        assert_eq!(
            blake3::keyed_hash(key, &input(n)).as_bytes(),
            &arr::<32>(keyed)
        );
    }
}

// -------------------------------------------------------- EnvCloak formats

const VAULT_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const EPOCH: u32 = 7;
const PASSPHRASE: &[u8] = b"envcloak envelope known answer";

/// Fields table, field value, secret item, schema 1, row version 42, row id
/// 0x10..0x1f.
fn kat_aad() -> Aad {
    Aad {
        vault_id: VaultId(VAULT_ID),
        schema_version: 1,
        key_epoch: EPOCH,
        table: TableTag::Fields,
        row_id: range(0x10),
        field: FieldTag::FieldValue,
        item_class: ItemClass::Secret,
        row_version: 42,
    }
}

/// A passphrase envelope of the VMK 0x20..0x3f for unlocker 0x50..0x5f,
/// with m = 64 MiB, t = 2, p = 1, salt 0x60..0x6f and nonce 0x70..0x87.
const ENVELOPE: &str = "
    454345560101505152535455565758595a5b5c5d5e5f0000000701000100000000000200000001606162
    636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868763ac42c70c
    d503f7143f1e9be31decd03c3474a4710ae7eead62516b570e51c93c8850368b913e272860cbc632620a
    a71154c6cee7aaaec003d486265fc4b66963e53b8afa5c52d7e4b245ad22da0a84";

/// keyed_hash(subkey, "envcloak/v1/kat", "abc") for each purpose of the
/// VMK above, in `Purpose::ALL` order.
const KEYED_HASHES: [&str; 8] = [
    "515554f6d90c44bc64652dd7a67341f2ffc1612f08746afbbc5f7205efab725f",
    "40c5c2c05ca099325cd2e8f5c2a6acec05f3a15aef8fcc27a71f482090cebbab",
    "14b59596306c7e708d7c3105040fe4c6f344ffd2275dcceb7e1a524b9a621e63",
    "ba5a3324572a3af13582011248d6a4b679f74f297034370c7ef73939c2815e34",
    "8175a0957131955e490b7e2b9add6578c0379cbf3b17043299919171c0430c0e",
    "e63feabc1324f3e5d660e907d26d09d8637013b3a0fba4dd716a65e6a7dd5ebb",
    "4d9ec26225a91f333fdf59a251117351818860ff37065d77803fda1a1235a1c5",
    "24f1af9d62c4bd84be40deb2fb82f85a1d6c3f4a8c9be8a113e4b5bd98641977",
];

/// "envcloak open known answer" sealed under the data subkey with
/// `kat_aad()` and nonce 0x40..0x57.
const SEALED: &str = "
    404142434445464748494a4b4c4d4e4f50515253545556573ac8244678c2bf3f1ac8b6f38400d10f2891
    861ab6665811c619294953eb8e62e6748a1f495bf20a6276";

fn kat_ctx() -> EnvelopeCtx {
    EnvelopeCtx {
        vault_id: VaultId(VAULT_ID),
        unlocker_id: UnlockerId(range(0x50)),
        epoch: EPOCH,
    }
}

fn kat_keyring() -> Keyring {
    let env = Envelope::from_bytes(&unhex(ENVELOPE)).unwrap();
    let vmk = unwrap_vmk(&env, &SecretBytes::copy_from(PASSPHRASE), &kat_ctx()).unwrap();
    Keyring::derive(&vmk, &VaultId(VAULT_ID), EPOCH)
}

#[test]
fn the_associated_data_encoding_matches_the_vector() {
    assert_eq!(
        kat_aad().encode().to_vec(),
        unhex(
            "01000102030405060708090a0b0c0d0e0f0001000000070003101112131415161718191a1b1c1d1e
             1f00040001000000000000002a"
        )
    );
}

#[test]
fn an_envelope_built_elsewhere_parses_and_unwraps() {
    let bytes = unhex(ENVELOPE);
    let env = Envelope::from_bytes(&bytes).unwrap();
    assert_eq!(env.kind(), UnlockerKind::Passphrase);
    assert_eq!(env.unlocker_id(), UnlockerId(range(0x50)));
    assert_eq!(env.epoch(), EPOCH);
    let k = env.kdf();
    assert_eq!((k.m_kib, k.t, k.p), (65536, 2, 1));
    assert_eq!(k.salt, range::<16>(0x60));
    assert_eq!(env.to_bytes().to_vec(), bytes);

    // Unwrapping gives the VMK whose subkeys hash as computed elsewhere.
    let kr = kat_keyring();
    for (p, want) in Purpose::ALL.into_iter().zip(KEYED_HASHES) {
        assert_eq!(
            keyed_hash(kr.key(p), "envcloak/v1/kat", b"abc"),
            arr::<32>(want),
            "{p:?}"
        );
    }

    let e = unwrap_vmk(
        &env,
        &SecretBytes::copy_from(b"envcloak envelope known answes"),
        &kat_ctx(),
    )
    .unwrap_err();
    assert_eq!(e.kind(), CryptoErrorKind::Unlock);
}

#[test]
fn a_value_sealed_elsewhere_opens() {
    let kr = kat_keyring();
    let sealed = Sealed::from_bytes(&unhex(SEALED)).unwrap();
    assert_eq!(sealed.nonce, range::<24>(0x40));
    let got = open(kr.key(Purpose::Data), &kat_aad(), &sealed).unwrap();
    assert!(got.ct_eq(b"envcloak open known answer"));

    // The same bytes under another purpose's key, or bound elsewhere, fail.
    let e = open(kr.key(Purpose::Header), &kat_aad(), &sealed).unwrap_err();
    assert_eq!(e.kind(), CryptoErrorKind::Open);
    let moved = Aad {
        row_version: 43,
        ..kat_aad()
    };
    let e = open(kr.key(Purpose::Data), &moved, &sealed).unwrap_err();
    assert_eq!(e.kind(), CryptoErrorKind::Open);
}
