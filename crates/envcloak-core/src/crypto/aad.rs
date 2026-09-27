//! Canonical associated data for sealed values (SPEC §5 "Vault"; layout in
//! docs/CRYPTO.md).
//!
//! Every sealed value is bound to (vault_id, schema_version, key_epoch,
//! table, row_id, field, item_class, row_version). The encoding is fixed
//! width and big-endian, starts with a format version byte, and uses no
//! serializer, so the same tuple always gives the same bytes. A ciphertext
//! moved to another row, field, table or item class, or replayed at another
//! row version or key epoch, fails to open.

use super::keys::VaultId;

/// The table a sealed value is stored in. The numbers are part of the vault
/// format: never renumber or reuse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TableTag {
    Header = 1,
    Items = 2,
    Fields = 3,
    Projects = 4,
    Policies = 5,
    Audit = 6,
    /// `unlockers` rows hold envelopes, which authenticate themselves, so
    /// no sealed value uses this tag; it names the table's rows in the
    /// vault's state digest.
    Unlockers = 7,
}

/// The column a sealed value is stored in. Part of the vault format, like
/// [`TableTag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum FieldTag {
    /// `header.sealed`.
    Header = 1,
    /// `items.sealed_meta`.
    ItemMeta = 2,
    /// `fields.sealed_name`.
    FieldName = 3,
    /// `fields.sealed_value`.
    FieldValue = 4,
    /// `fields.sealed_prior`.
    FieldPrior = 5,
    /// `projects.sealed`.
    Project = 6,
    /// `policies.sealed`.
    Policy = 7,
    /// An audit log entry.
    AuditEntry = 8,
}

/// The class of the item a sealed value belongs to (SPEC §5 "Items").
/// [`ItemClass::None`] for rows that are not items. Part of the vault
/// format, like [`TableTag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ItemClass {
    None = 0,
    Secret = 1,
    Card = 2,
    IssuerCredential = 3,
}

/// The associated data of one sealed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Aad {
    pub vault_id: VaultId,
    pub schema_version: u16,
    pub key_epoch: u32,
    pub table: TableTag,
    pub row_id: [u8; 16],
    pub field: FieldTag,
    pub item_class: ItemClass,
    pub row_version: u64,
}

impl Aad {
    /// Length of [`Aad::encode`]'s output.
    pub const LEN: usize = 53;
    /// The first byte of the encoding.
    pub const FORMAT_VERSION: u8 = 1;

    /// The canonical encoding:
    /// `version(1) vault_id(16) schema_version(2) key_epoch(4) table(2)
    /// row_id(16) field(2) item_class(2) row_version(8)`, integers
    /// big-endian.
    pub fn encode(&self) -> [u8; Aad::LEN] {
        let mut out = [0u8; Aad::LEN];
        let mut w = Writer {
            buf: &mut out,
            at: 0,
        };
        w.put(&[Aad::FORMAT_VERSION]);
        w.put(&self.vault_id.0);
        w.put(&self.schema_version.to_be_bytes());
        w.put(&self.key_epoch.to_be_bytes());
        w.put(&(self.table as u16).to_be_bytes());
        w.put(&self.row_id);
        w.put(&(self.field as u16).to_be_bytes());
        w.put(&(self.item_class as u16).to_be_bytes());
        w.put(&self.row_version.to_be_bytes());
        debug_assert_eq!(w.at, Aad::LEN);
        out
    }
}

struct Writer<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, b: &[u8]) {
        self.buf[self.at..self.at + b.len()].copy_from_slice(b);
        self.at += b.len();
    }
}
