//! Vault errors. Each kind has a fixed message; none carries a value, a
//! bound parameter, a path or upstream error text (SPEC §5 "Logging").

use crate::crypto::{CryptoError, CryptoErrorKind};
use crate::passphrase::PassphraseRejected;

use super::paths::{PathError, PathErrorKind};

/// A vault failure. Carries its kind only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultError {
    kind: VaultErrorKind,
}

/// What went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VaultErrorKind {
    /// No vault file exists at the location.
    NotFound,
    /// `create` found a vault already there.
    AlreadyExists,
    /// Another process, or another handle in this one, has the vault open.
    Busy,
    /// A vault directory or file failed its ownership or permission check.
    Path(PathErrorKind),
    /// A filesystem operation outside SQLite failed.
    Io(std::io::ErrorKind),
    /// SQLite failed, with its extended result code.
    Storage(i32),
    /// The disk is full; nothing was written.
    DiskFull,
    /// The file is not an EnvCloak vault, or its plaintext columns are
    /// malformed.
    Damaged,
    /// The vault was written by a newer schema than this build reads.
    UnsupportedVersion,
    /// A format migration failed and was rolled back; the vault is as it
    /// was, and open read-only.
    Migration,
    /// The key opens nothing in this vault: a wrong VMK, or a vault whose
    /// every sealed row is damaged.
    KeyMismatch,
    /// Sealed data did not open, or a row differs from the verified state:
    /// the vault was changed outside EnvCloak.
    Tampered,
    /// The vault is open read-only because it failed its integrity check.
    ReadOnly,
    /// Encryption failed.
    Crypto(CryptoErrorKind),
    InvalidSlug,
    InvalidFieldName,
    /// A record's other fields are invalid (an item class of `None`, an
    /// envelope from another epoch, an empty project key).
    InvalidRecord,
    /// An empty secret value.
    InvalidValue,
    /// A value or record exceeds its size cap.
    TooLarge,
    DuplicateSlug,
    DuplicateField,
    DuplicateUnlocker,
    UnknownItem,
    UnknownField,
    UnknownUnlocker,
    /// Removing the vault's last unlocker would leave no way to open it.
    LastUnlocker,
    /// A new passphrase breaks the passphrase rules.
    Passphrase(PassphraseRejected),
    /// An authenticated record failed to decode: a bug, not an attack.
    Corrupt,
}

impl VaultErrorKind {
    /// The fixed message for this kind.
    pub fn message(self) -> &'static str {
        match self {
            VaultErrorKind::NotFound => "no vault exists at this location",
            VaultErrorKind::AlreadyExists => "a vault already exists at this location",
            VaultErrorKind::Busy => "the vault is open in another process",
            VaultErrorKind::Path(k) => k.message(),
            VaultErrorKind::Io(_) => "vault file access failed",
            VaultErrorKind::Storage(_) => "vault storage failed",
            VaultErrorKind::DiskFull => "the disk is full",
            VaultErrorKind::Damaged => "the vault file is damaged or is not an EnvCloak vault",
            VaultErrorKind::UnsupportedVersion => {
                "the vault was written by a newer version of EnvCloak"
            }
            VaultErrorKind::Migration => {
                "upgrading the vault format failed; the vault is unchanged"
            }
            VaultErrorKind::KeyMismatch => {
                "the key does not open this vault, or the vault is damaged"
            }
            VaultErrorKind::Tampered => "the vault was modified outside EnvCloak",
            VaultErrorKind::ReadOnly => {
                "the vault is read-only because it was modified outside EnvCloak"
            }
            VaultErrorKind::Crypto(k) => k.message(),
            VaultErrorKind::InvalidSlug => {
                "invalid item name: use lowercase letters, digits, '.', '_' and '-', \
                 with '/' between parts, up to 128 bytes"
            }
            VaultErrorKind::InvalidFieldName => {
                "invalid field name: use lowercase letters, digits, '.', '_' and '-', \
                 up to 64 bytes"
            }
            VaultErrorKind::InvalidRecord => "invalid item, project or unlocker data",
            VaultErrorKind::InvalidValue => "a secret value must not be empty",
            VaultErrorKind::TooLarge => "a value or record exceeds the vault's size limit",
            VaultErrorKind::DuplicateSlug => "an item with this name already exists",
            VaultErrorKind::DuplicateField => "the item already has a field with this name",
            VaultErrorKind::DuplicateUnlocker => "the vault already has this unlocker",
            VaultErrorKind::UnknownItem => "no such item",
            VaultErrorKind::UnknownField => "no such field",
            VaultErrorKind::UnknownUnlocker => "no such unlocker",
            VaultErrorKind::LastUnlocker => "the vault's last unlocker cannot be removed",
            VaultErrorKind::Passphrase(r) => r.message(),
            VaultErrorKind::Corrupt => "a sealed vault record could not be decoded",
        }
    }
}

impl VaultError {
    pub fn kind(&self) -> VaultErrorKind {
        self.kind
    }
}

impl From<VaultErrorKind> for VaultError {
    fn from(kind: VaultErrorKind) -> Self {
        VaultError { kind }
    }
}

impl From<PathError> for VaultError {
    fn from(e: PathError) -> Self {
        match e.kind() {
            PathErrorKind::Missing => VaultErrorKind::NotFound.into(),
            k => VaultErrorKind::Path(k).into(),
        }
    }
}

impl From<PassphraseRejected> for VaultError {
    fn from(r: PassphraseRejected) -> Self {
        VaultErrorKind::Passphrase(r).into()
    }
}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        VaultErrorKind::Crypto(e.kind()).into()
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultErrorKind::Io(e.kind()).into()
    }
}

/// Maps a SQLite error to a kind. The message SQLite attached, and any
/// text rusqlite carries (SQL, a column name, a path), is dropped.
impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        use rusqlite::ErrorCode;
        let kind = match &e {
            rusqlite::Error::SqliteFailure(f, _) => match f.code {
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => VaultErrorKind::Busy,
                ErrorCode::DiskFull => VaultErrorKind::DiskFull,
                ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => VaultErrorKind::Damaged,
                _ => VaultErrorKind::Storage(f.extended_code),
            },
            // A column of the wrong type or size, or a row missing where
            // one must be: the file's plaintext layout was altered.
            rusqlite::Error::QueryReturnedNoRows
            | rusqlite::Error::QueryReturnedMoreThanOneRow
            | rusqlite::Error::InvalidColumnType(..)
            | rusqlite::Error::InvalidColumnIndex(_)
            | rusqlite::Error::InvalidColumnName(_)
            | rusqlite::Error::IntegralValueOutOfRange(..)
            | rusqlite::Error::FromSqlConversionFailure(..) => VaultErrorKind::Damaged,
            _ => VaultErrorKind::Storage(-1),
        };
        kind.into()
    }
}

impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.kind.message())
    }
}

impl std::error::Error for VaultError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_the_fixed_message() {
        for k in [
            VaultErrorKind::NotFound,
            VaultErrorKind::Busy,
            VaultErrorKind::Storage(2067),
            VaultErrorKind::Io(std::io::ErrorKind::PermissionDenied),
            VaultErrorKind::Path(PathErrorKind::Symlink),
            VaultErrorKind::Crypto(CryptoErrorKind::Seal),
            VaultErrorKind::Tampered,
            VaultErrorKind::Corrupt,
            VaultErrorKind::Passphrase(PassphraseRejected::Common),
        ] {
            let e = VaultError::from(k);
            assert_eq!(e.to_string(), k.message());
            assert!(std::error::Error::source(&e).is_none());
        }
    }

    #[test]
    fn sqlite_errors_drop_their_text() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t(x BLOB UNIQUE)").unwrap();
        let marker = "a-bound-parameter-marker";
        conn.execute("INSERT INTO t VALUES (?1)", [marker]).unwrap();
        let raw = conn
            .execute("INSERT INTO t VALUES (?1)", [marker])
            .unwrap_err();
        let e = VaultError::from(raw);
        // SQLITE_CONSTRAINT_UNIQUE.
        assert_eq!(e.kind(), VaultErrorKind::Storage(2067));
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains(marker) && !shown.contains("t.x"), "{shown}");
    }
}
