//! EnvCloak core: secret types, and (in later M1 tasks) crypto, the vault
//! format and storage, unlockers, backups and the audit log.

pub mod secret;

pub use secret::{CapacityExceeded, SecretBuf, SecretBytes};
