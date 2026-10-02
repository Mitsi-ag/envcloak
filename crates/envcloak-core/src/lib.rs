//! EnvCloak core: secret types, crypto, vault storage, unlockers and the
//! Recovery Kit, encrypted backups, and the audit log.
//!
//! The `testing` feature adds test support that release binaries never
//! enable: `crypto::Vmk::export_for_testing` and `import_for_testing`,
//! `vault::LockedVault::open_with_plan`,
//! `vault::Vault::change_passphrase_for_testing`,
//! `backup::restore_backup_observed`, `backup::restore_backup_with_plan`,
//! `file_backup::age_file_backup_for_testing`,
//! `vault::Vault::begin_file_backup_v2_observed` and
//! `file_backup_v2::age_file_backup_v2_for_testing`.

pub mod audit;
pub mod backup;
pub mod crypto;
pub mod file_backup;
pub mod file_backup_v2;
pub mod passphrase;
pub mod recovery;
pub mod secret;
pub mod unlock;
pub mod vault;
mod wordlists;

pub use backup::{BackupInfo, RestoreReport, restore_backup};
pub use passphrase::{PassphraseRejected, check_passphrase, suggest_passphrase};
pub use recovery::{KitError, RecoveryKit};
pub use secret::{CapacityExceeded, SecretBuf, SecretBytes};
pub use unlock::{create_vault, create_vault_with_kit};
