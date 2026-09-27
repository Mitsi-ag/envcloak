//! A verified copy of the vault's database, for a backup (see
//! crate::backup).
//!
//! The image is read through the vault's own connection with
//! `sqlite3_serialize`, so it is the committed state whatever part of it
//! still sits in the WAL, and it holds exactly what the vault file holds:
//! sealed columns, keyed hashes, ids, row versions and timestamps. It is
//! marked as a rollback-journal database (the WAL is already folded in), so
//! it opens without side files. Before it is handed out it is opened in
//! memory and verified with the vault's keys: the digest must verify and
//! the header must be the one this process last committed. A file changed
//! behind the vault's back therefore never becomes a backup; the vault
//! turns read-only instead, as for any other change found while open. So
//! does a file that can no longer be read or opened as a database at all:
//! whatever the reason, a vault that cannot produce a verified image of
//! itself is no longer trusted until an unlock verifies it again.

use rusqlite::{Connection, MAIN_DB};

use super::error::{VaultError, VaultErrorKind};
use super::integrity::{Integrity, TamperKind};
use super::{Vault, schema, state};

/// Offsets of the file format write and read versions in a SQLite header:
/// 1 for rollback journal, 2 for WAL.
const FORMAT_VERSIONS: [usize; 2] = [18, 19];
const SQLITE_HEADER_LEN: usize = 100;

impl Vault {
    /// The database image, verified. Refused with
    /// [`VaultErrorKind::Tampered`] unless the vault verified at unlock and
    /// still matches what this process committed; any failure to read or
    /// verify the image turns the vault read-only
    /// ([`TamperKind::ChangedWhileOpen`]) and is reported as tampering.
    pub(crate) fn snapshot(&self) -> Result<Vec<u8>, VaultError> {
        self.trusted()?;
        self.verified_image().map_err(|_| {
            self.integrity
                .set(Integrity::Tampered(TamperKind::ChangedWhileOpen));
            VaultErrorKind::Tampered.into()
        })
    }

    fn verified_image(&self) -> Result<Vec<u8>, VaultError> {
        // Read the file as it is now, not pages cached before another
        // program changed it.
        schema::drop_page_cache(&self.file.conn)?;
        let mut image = {
            let data = self.file.conn.serialize(MAIN_DB)?;
            let mut v = Vec::with_capacity(data.len());
            v.extend_from_slice(&data);
            v
        };
        if image.len() < SQLITE_HEADER_LEN {
            return Err(VaultErrorKind::Damaged.into());
        }
        for at in FORMAT_VERSIONS {
            if image[at] == 2 {
                image[at] = 1;
            }
        }
        if !self.image_matches(&image)? {
            return Err(VaultErrorKind::Tampered.into());
        }
        Ok(image)
    }

    /// Whether `image` opens as this vault, with a verified digest and the
    /// header this process last committed.
    fn image_matches(&self, image: &[u8]) -> Result<bool, VaultError> {
        let mut mem = Connection::open_in_memory()?;
        schema::harden_connection(&mem)?;
        mem.deserialize_read_exact(MAIN_DB, image, image.len(), true)?;
        let schema_ok = schema::verify_schema(&mem, self.ctx.schema_version, &self.file.plan)?;
        let loaded = match state::load(&mem, &self.keys, &self.ctx, schema_ok) {
            Ok(l) => l,
            Err(e) if e.kind() == VaultErrorKind::KeyMismatch => return Ok(false),
            Err(e) => return Err(e),
        };
        Ok(loaded.integrity == Integrity::Ok && loaded.state.header == self.state.header)
    }
}
