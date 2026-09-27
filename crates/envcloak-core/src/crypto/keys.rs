//! The key hierarchy below the VMK (SPEC §5 "Key hierarchy").
//!
//! - [`Vmk`]: the random 256-bit Vault Master Key of one epoch.
//! - [`Keyring`]: one [`SubKey`] per [`Purpose`], each
//!   HKDF-SHA256(ikm = VMK, salt = vault_id, info =
//!   `envcloak/v1/<purpose>/e<epoch>`), the epoch in decimal.
//! - [`keyed_hash`]: keyed BLAKE3 under a subkey, with a domain label.
//!
//! Key bytes live in `secrecy` boxes, wiped on drop. They are read only in
//! the crypto files security/expose-allowlist.txt lists.

use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::fill_random_or_panic;

/// A vault's random identifier. Not secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VaultId(pub [u8; 16]);

impl VaultId {
    /// A new random identifier.
    ///
    /// # Panics
    /// When the OS random number generator fails.
    pub fn generate() -> Self {
        let mut id = [0u8; 16];
        fill_random_or_panic(&mut id);
        VaultId(id)
    }
}

/// An unlocker's random identifier. Not secret.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnlockerId(pub [u8; 16]);

impl UnlockerId {
    /// A new random identifier.
    ///
    /// # Panics
    /// When the OS random number generator fails.
    pub fn generate() -> Self {
        let mut id = [0u8; 16];
        fill_random_or_panic(&mut id);
        UnlockerId(id)
    }
}

fn hex_id(f: &mut core::fmt::Formatter<'_>, name: &str, id: &[u8; 16]) -> core::fmt::Result {
    write!(f, "{name}(")?;
    for b in id {
        write!(f, "{b:02x}")?;
    }
    f.write_str(")")
}

impl core::fmt::Debug for VaultId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        hex_id(f, "VaultId", &self.0)
    }
}

impl core::fmt::Debug for UnlockerId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        hex_id(f, "UnlockerId", &self.0)
    }
}

/// The Vault Master Key of one epoch. Never stored in plaintext: it exists
/// wrapped in unlocker envelopes and, while the vault is unlocked, here.
pub struct Vmk(pub(crate) SecretBox<[u8; 32]>);

impl Vmk {
    /// A new random VMK from the OS CSPRNG, written straight into its heap
    /// box.
    ///
    /// # Panics
    /// When the OS random number generator fails.
    pub fn generate() -> Self {
        Vmk(SecretBox::init_with_mut(|k: &mut [u8; 32]| {
            fill_random_or_panic(k)
        }))
    }

    /// Whether two VMKs are the same key, compared in constant time: a
    /// Recovery Kit is confirmed only when its envelope holds this vault's
    /// VMK.
    #[allow(clippy::disallowed_methods)] // Compares two keys without revealing either.
    pub(crate) fn ct_eq(&self, other: &Vmk) -> bool {
        bool::from(self.0.expose_secret().ct_eq(other.0.expose_secret()))
    }
}

impl core::fmt::Debug for Vmk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Vmk(..)")
    }
}

/// Test support only (feature `testing`): moving a VMK between processes,
/// so crash tests can reopen a vault without running Argon2 each time.
/// Release binaries never enable the feature.
#[cfg(feature = "testing")]
impl Vmk {
    /// The key's bytes, as a plain vector for a test to hand to a child
    /// process.
    #[allow(clippy::disallowed_methods)] // Test support: copies the key out.
    pub fn export_for_testing(&self) -> Vec<u8> {
        self.0.expose_secret().to_vec()
    }

    /// A VMK from [`Vmk::export_for_testing`]'s bytes; `None` unless there
    /// are exactly 32.
    pub fn import_for_testing(b: &[u8]) -> Option<Self> {
        let b: &[u8; 32] = b.try_into().ok()?;
        Some(Vmk(SecretBox::init_with_mut(|k: &mut [u8; 32]| {
            k.copy_from_slice(b)
        })))
    }
}

/// What a subkey is for. Each purpose has its own key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    Data,
    /// Keyed BLAKE3 for lookups (slug and value hashes).
    Index,
    Audit,
    Sync,
    Card,
    Backup,
    Header,
    Anchor,
}

impl Purpose {
    /// Every purpose, in declaration order.
    pub const ALL: [Purpose; 8] = [
        Purpose::Data,
        Purpose::Index,
        Purpose::Audit,
        Purpose::Sync,
        Purpose::Card,
        Purpose::Backup,
        Purpose::Header,
        Purpose::Anchor,
    ];

    /// The `<purpose>` part of the HKDF info.
    pub const fn label(self) -> &'static str {
        match self {
            Purpose::Data => "data",
            Purpose::Index => "index",
            Purpose::Audit => "audit",
            Purpose::Sync => "sync",
            Purpose::Card => "card",
            Purpose::Backup => "backup",
            Purpose::Header => "header",
            Purpose::Anchor => "anchor",
        }
    }
}

/// One 256-bit subkey.
pub struct SubKey {
    purpose: Purpose,
    pub(crate) key: SecretBox<[u8; 32]>,
}

impl SubKey {
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
}

impl core::fmt::Debug for SubKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SubKey({}, ..)", self.purpose.label())
    }
}

/// The subkeys of one VMK epoch.
pub struct Keyring {
    vault_id: VaultId,
    epoch: u32,
    /// Indexed by `Purpose as usize`.
    keys: [SubKey; 8],
}

impl Keyring {
    /// Derives every subkey of `vmk` for `vault_id` and `epoch`. Each key is
    /// written straight into its heap box.
    #[allow(clippy::disallowed_methods)] // Reads the VMK to derive subkeys.
    pub fn derive(vmk: &Vmk, vault_id: &VaultId, epoch: u32) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(&vault_id.0), vmk.0.expose_secret());
        let epoch_label = epoch.to_string();
        let keys = Purpose::ALL.map(|purpose| SubKey {
            purpose,
            key: SecretBox::init_with_mut(|k: &mut [u8; 32]| {
                hkdf_expand(
                    &hk,
                    &[
                        b"envcloak/v1/",
                        purpose.label().as_bytes(),
                        b"/e",
                        epoch_label.as_bytes(),
                    ],
                    k,
                )
            }),
        });
        Keyring {
            vault_id: *vault_id,
            epoch,
            keys,
        }
    }

    pub fn key(&self, p: Purpose) -> &SubKey {
        &self.keys[p as usize]
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }
}

impl core::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keyring")
            .field("vault_id", &self.vault_id)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// HKDF-Expand to 32 bytes; the info is the concatenation of `info`.
pub(crate) fn hkdf_expand(hk: &Hkdf<Sha256>, info: &[&[u8]], out: &mut [u8; 32]) {
    hk.expand_multi_info(info, out)
        .expect("32 bytes is within the HKDF-SHA256 output limit");
}

/// Keyed BLAKE3 of the concatenation of `parts`. The hasher, which holds
/// the key and buffered input, is wiped before returning.
pub(crate) fn blake3_keyed(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(key);
    for p in parts {
        h.update(p);
    }
    let out = *h.finalize().as_bytes();
    h.zeroize();
    out
}

/// Keyed BLAKE3 under `k` of `u32be(len(domain)) || domain || v`. The
/// length prefix keeps every (domain, value) pair distinct.
#[allow(clippy::disallowed_methods)] // Reads the subkey to key the hash.
pub fn keyed_hash(k: &SubKey, domain: &'static str, v: &[u8]) -> [u8; 32] {
    let len = u32::try_from(domain.len()).expect("domain labels are short");
    blake3_keyed(
        k.key.expose_secret(),
        &[&len.to_be_bytes(), domain.as_bytes(), v],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn okm(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        hkdf_expand(&Hkdf::<Sha256>::new(salt, ikm), &[info], &mut out);
        out
    }

    /// RFC 5869 appendix A, test cases 1 to 3 (SHA-256). Every EnvCloak
    /// derivation takes 32 bytes, the first 32 of each case's OKM.
    #[test]
    fn hkdf_expand_matches_rfc5869() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        assert_eq!(
            okm(Some(&salt), &ikm, &info)[..],
            unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")[..]
        );

        let ikm: Vec<u8> = (0x00..=0x4f).collect();
        let salt: Vec<u8> = (0x60..=0xaf).collect();
        let info: Vec<u8> = (0xb0..=0xff).collect();
        assert_eq!(
            okm(Some(&salt), &ikm, &info)[..],
            unhex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c")[..]
        );

        // Case 3: no salt and no info. An absent salt is HashLen zeros.
        let ikm = [0x0bu8; 22];
        let want = unhex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d");
        assert_eq!(okm(None, &ikm, &[])[..], want[..]);
        assert_eq!(okm(Some(&[0u8; 32]), &ikm, &[])[..], want[..]);
    }

    #[test]
    fn info_is_concatenated() {
        let hk = Hkdf::<Sha256>::new(Some(b"salt"), b"input key material");
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        hkdf_expand(&hk, &[b"envcloak/v1/", b"data", b"/e", b"12"], &mut a);
        hkdf_expand(&hk, &[b"envcloak/v1/data/e12"], &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn purposes_have_distinct_labels_in_index_order() {
        for (i, p) in Purpose::ALL.iter().enumerate() {
            assert_eq!(*p as usize, i);
        }
        let labels: std::collections::HashSet<_> = Purpose::ALL.iter().map(|p| p.label()).collect();
        assert_eq!(labels.len(), Purpose::ALL.len());
    }

    #[test]
    #[allow(clippy::disallowed_methods)] // Compares the derived keys.
    fn keyring_keys_are_distinct_and_tagged() {
        let kr = Keyring::derive(&Vmk::generate(), &VaultId::generate(), 3);
        let mut seen = std::collections::HashSet::new();
        for p in Purpose::ALL {
            assert_eq!(kr.key(p).purpose(), p);
            assert!(seen.insert(*kr.key(p).key.expose_secret()));
        }
        assert_eq!(format!("{:?}", kr.key(Purpose::Index)), "SubKey(index, ..)");
        assert_eq!(format!("{:?}", Vmk::generate()), "Vmk(..)");
    }

    #[test]
    fn blake3_keyed_matches_published_vectors() {
        // BLAKE3 test_vectors.json: key "whats the Elvish word for friend",
        // inputs of 0 and 1 bytes of (i % 251).
        let key = b"whats the Elvish word for friend";
        assert_eq!(
            blake3_keyed(key, &[])[..],
            unhex("92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26")[..]
        );
        assert_eq!(
            blake3_keyed(key, &[&[], &[0u8], &[]])[..],
            unhex("6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b")[..]
        );
    }
}
