//! EnvCloak core: secret types, crypto and vault storage, and (in later M1
//! tasks) unlockers, backups and the audit log.
//!
//! The `testing` feature adds test support that release binaries never
//! enable: `crypto::Vmk::export_for_testing` and `import_for_testing`, and
//! `vault::LockedVault::open_with_plan`.

pub mod crypto;
pub mod secret;
pub mod vault;

pub use secret::{CapacityExceeded, SecretBuf, SecretBytes};
