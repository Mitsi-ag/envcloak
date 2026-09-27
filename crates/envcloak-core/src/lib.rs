//! EnvCloak core: secret types and crypto, and (in later M1 tasks) the
//! vault format and storage, unlockers, backups and the audit log.

pub mod crypto;
pub mod secret;

pub use secret::{CapacityExceeded, SecretBuf, SecretBytes};
