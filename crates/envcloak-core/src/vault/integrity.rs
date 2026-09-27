//! The sealed header and the state digest (SPEC §5 "Integrity"; layouts in
//! docs/VAULT.md).
//!
//! Every row of `unlockers`, `items`, `fields`, `projects` and `policies`
//! has a stamp: its row version and the SHA-256 of its stored columns. The
//! state digest is keyed BLAKE3, under the `header` subkey, over the stamps
//! sorted by (table, row id). The header, sealed under the same subkey,
//! holds the digest and a write counter and is rewritten in the same
//! SQLite transaction as every write.
//!
//! At unlock the digest is recomputed from the rows on disk. A deleted,
//! added or altered row, or one row restored from an older copy, changes it,
//! and the vault opens read-only. Restoring the whole file together with its
//! header is not detected locally (SPEC §5).
//!
//! While the vault is open, the digest is computed from the stamps in
//! memory, which only this process's own writes change, never from the
//! file: a row altered behind the daemon's back is not folded into a fresh
//! digest, so it is still caught at the next unlock.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::crypto::{Keyring, Purpose, TableTag, keyed_hash};

use super::codec::{Dec, Enc};
use super::error::{VaultError, VaultErrorKind};

/// The audit log's head as last saved in the header (T10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditHead {
    pub seq: u64,
    pub mac: [u8; 32],
}

/// The contents of the sealed header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeaderState {
    /// Counts committed writes: 1 after `create`, one more per write
    /// transaction.
    pub write_counter: u64,
    /// The state digest at the last commit.
    pub state_digest: [u8; 32],
    /// Bumped when a policy change must invalidate grants (T9).
    pub policy_epoch: u64,
    pub audit_head: Option<AuditHead>,
    /// The user proved they hold the Recovery Kit (T4).
    pub recovery_confirmed: bool,
}

const HEADER_RECORD: u8 = 1;

impl HeaderState {
    /// `version(1) write_counter(8) state_digest(32) policy_epoch(8)
    /// audit_present(1) audit_seq(8) audit_mac(32) recovery_confirmed(1)`.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let head = self.audit_head.unwrap_or(AuditHead {
            seq: 0,
            mac: [0; 32],
        });
        let mut e = Enc::new();
        e.u8(HEADER_RECORD)
            .u64(self.write_counter)
            .raw(&self.state_digest)
            .u64(self.policy_epoch)
            .u8(u8::from(self.audit_head.is_some()))
            .u64(head.seq)
            .raw(&head.mac)
            .u8(u8::from(self.recovery_confirmed));
        e.finish()
    }

    pub(crate) fn decode(b: &[u8]) -> Result<Self, VaultError> {
        let mut d = Dec::new(b);
        if d.u8()? != HEADER_RECORD {
            return Err(VaultErrorKind::Corrupt.into());
        }
        let write_counter = d.u64()?;
        let state_digest = d.array()?;
        let policy_epoch = d.u64()?;
        let present = d.bool()?;
        let head = AuditHead {
            seq: d.u64()?,
            mac: d.array()?,
        };
        let recovery_confirmed = d.bool()?;
        d.end()?;
        Ok(HeaderState {
            write_counter,
            state_digest,
            policy_epoch,
            audit_head: present.then_some(head),
            recovery_confirmed,
        })
    }
}

/// Whether the vault passed its integrity check at unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    Ok,
    /// The vault is open read-only: writes fail with
    /// [`VaultErrorKind::ReadOnly`]. Readable items and values stay
    /// available so their owner can recover them.
    Tampered(TamperKind),
}

/// The first integrity failure found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TamperKind {
    /// The header is missing, duplicated or does not open, while other rows
    /// open under the same key.
    HeaderUnreadable,
    /// The rows do not match the digest in the header: a row was deleted,
    /// added, altered or restored from an older copy.
    DigestMismatch,
    /// A sealed row does not open.
    RowUnreadable,
    /// A row's plaintext columns disagree with its sealed contents (a keyed
    /// hash, an item reference, an unlocker's kind or id).
    RowInconsistent,
    /// The database holds tables, indexes, triggers or views the vault
    /// format does not define.
    SchemaAltered,
    /// A row changed on disk while this process had the vault open.
    ChangedWhileOpen,
}

impl TamperKind {
    pub fn message(self) -> &'static str {
        match self {
            TamperKind::HeaderUnreadable => "the vault header is missing or damaged",
            TamperKind::DigestMismatch => {
                "vault rows were deleted, added, altered or restored from an older copy"
            }
            TamperKind::RowUnreadable => "a sealed vault row does not open",
            TamperKind::RowInconsistent => "a vault row's columns disagree with its sealed data",
            TamperKind::SchemaAltered => "the vault database's schema was altered",
            TamperKind::ChangedWhileOpen => "a vault row changed on disk while the vault was open",
        }
    }
}

/// A row's place in the digest: its table tag and id.
pub(crate) type RowKey = (u16, [u8; 16]);

/// A row's version and the SHA-256 of its stored columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stamp {
    pub row_version: u64,
    pub body: [u8; 32],
}

pub(crate) fn row_key(table: TableTag, id: &[u8; 16]) -> RowKey {
    (table as u16, *id)
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn len32(b: &[u8]) -> [u8; 4] {
    u32::try_from(b.len()).unwrap_or(u32::MAX).to_be_bytes()
}

/// `unlockers`: `kind(8) created_at(8) envelope`.
pub(crate) fn unlocker_body(kind: i64, created_at: i64, envelope: &[u8]) -> [u8; 32] {
    sha256(&[&kind.to_be_bytes(), &created_at.to_be_bytes(), envelope])
}

/// `items`: `class(8) len(4) slug_hash updated_at(8) sealed_meta`.
pub(crate) fn item_body(class: i64, slug_hash: &[u8], updated_at: i64, sealed: &[u8]) -> [u8; 32] {
    sha256(&[
        &class.to_be_bytes(),
        &len32(slug_hash),
        slug_hash,
        &updated_at.to_be_bytes(),
        sealed,
    ])
}

/// `fields`: `len(4) item_id len(4) value_hash len(4) sealed_name len(4)
/// sealed_value has_prior(1) [sealed_prior]`.
pub(crate) fn field_body(
    item_id: &[u8],
    value_hash: &[u8],
    sealed_name: &[u8],
    sealed_value: &[u8],
    sealed_prior: Option<&[u8]>,
) -> [u8; 32] {
    sha256(&[
        &len32(item_id),
        item_id,
        &len32(value_hash),
        value_hash,
        &len32(sealed_name),
        sealed_name,
        &len32(sealed_value),
        sealed_value,
        &[u8::from(sealed_prior.is_some())],
        sealed_prior.unwrap_or(&[]),
    ])
}

/// `projects`: `len(4) dir_hash sealed`.
pub(crate) fn project_body(dir_hash: &[u8], sealed: &[u8]) -> [u8; 32] {
    sha256(&[&len32(dir_hash), dir_hash, sealed])
}

/// `policies`: `sealed`.
pub(crate) fn policy_body(sealed: &[u8]) -> [u8; 32] {
    sha256(&[sealed])
}

/// The keyed-hash domain of the state digest.
pub(crate) const DIGEST_DOMAIN: &str = "envcloak/v1/state-digest";
const ENTRY_LEN: usize = 2 + 16 + 8 + 32;

/// Keyed BLAKE3 under the `header` subkey over every stamp, in (table, row
/// id) order: `table(2) row_id(16) row_version(8) body(32)` each.
pub(crate) fn state_digest(keys: &Keyring, stamps: &BTreeMap<RowKey, Stamp>) -> [u8; 32] {
    let mut entries = Vec::with_capacity(stamps.len() * ENTRY_LEN);
    for ((table, id), s) in stamps {
        entries.extend_from_slice(&table.to_be_bytes());
        entries.extend_from_slice(id);
        entries.extend_from_slice(&s.row_version.to_be_bytes());
        entries.extend_from_slice(&s.body);
    }
    keyed_hash(keys.key(Purpose::Header), DIGEST_DOMAIN, &entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{VaultId, Vmk};

    #[test]
    fn header_round_trips() {
        let mut h = HeaderState {
            write_counter: 9,
            state_digest: [3; 32],
            policy_epoch: 2,
            audit_head: None,
            recovery_confirmed: false,
        };
        assert_eq!(HeaderState::decode(&h.encode()).unwrap(), h);
        assert_eq!(h.encode().len(), 91);
        h.audit_head = Some(AuditHead {
            seq: 77,
            mac: [5; 32],
        });
        h.recovery_confirmed = true;
        assert_eq!(HeaderState::decode(&h.encode()).unwrap(), h);
        let mut bad = h.encode();
        bad[0] = 2;
        assert!(HeaderState::decode(&bad).is_err());
    }

    #[test]
    fn the_digest_covers_every_stamp_field_and_is_keyed() {
        let vid = VaultId::generate();
        let keys = Keyring::derive(&Vmk::generate(), &vid, 1);
        let mut stamps = BTreeMap::new();
        stamps.insert(
            row_key(TableTag::Items, &[1; 16]),
            Stamp {
                row_version: 1,
                body: [7; 32],
            },
        );
        stamps.insert(
            row_key(TableTag::Fields, &[2; 16]),
            Stamp {
                row_version: 3,
                body: [8; 32],
            },
        );
        let base = state_digest(&keys, &stamps);
        assert_eq!(base, state_digest(&keys, &stamps.clone()));

        let changed = |f: &dyn Fn(&mut BTreeMap<RowKey, Stamp>)| {
            let mut s = stamps.clone();
            f(&mut s);
            state_digest(&keys, &s)
        };
        let k = row_key(TableTag::Fields, &[2; 16]);
        assert_ne!(
            changed(&|s| {
                s.remove(&k);
            }),
            base
        );
        assert_ne!(changed(&|s| s.get_mut(&k).unwrap().row_version = 2), base);
        assert_ne!(changed(&|s| s.get_mut(&k).unwrap().body[0] ^= 1), base);
        assert_ne!(
            changed(&|s| {
                let v = s.remove(&k).unwrap();
                s.insert(row_key(TableTag::Projects, &[2; 16]), v);
            }),
            base
        );
        let other = Keyring::derive(&Vmk::generate(), &vid, 1);
        assert_ne!(state_digest(&other, &stamps), base);
    }

    #[test]
    fn bodies_separate_their_columns() {
        // Moving bytes between the name and the value changes the body.
        assert_ne!(
            field_body(&[0; 16], &[0; 32], b"ab", b"c", None),
            field_body(&[0; 16], &[0; 32], b"a", b"bc", None)
        );
        assert_ne!(
            field_body(&[0; 16], &[0; 32], b"a", b"b", None),
            field_body(&[0; 16], &[0; 32], b"a", b"b", Some(b""))
        );
    }
}
