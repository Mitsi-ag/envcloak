//! EnvCloak core: secret types, crypto, vault storage, passphrase rules and
//! the Recovery Kit, and (in later M1 tasks) unlockers, backups and the
//! audit log.
//!
//! The `testing` feature adds test support that release binaries never
//! enable: `crypto::Vmk::export_for_testing` and `import_for_testing`, and
//! `vault::LockedVault::open_with_plan`.

pub mod crypto;
pub mod passphrase;
pub mod recovery;
pub mod secret;
pub mod vault;
mod wordlists;

pub use passphrase::{PassphraseRejected, check_passphrase, suggest_passphrase};
pub use recovery::{KitError, RecoveryKit};
pub use secret::{CapacityExceeded, SecretBuf, SecretBytes};
