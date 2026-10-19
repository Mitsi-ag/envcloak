//! Candidate names stay private until validated for shared import metadata.
use super::Entry;
use envcloak_core::SecretBytes;

impl Entry {
    /// Safe environment metadata for the shared importer. Values and labels
    /// shaped like credentials never become report names.
    #[allow(clippy::disallowed_methods)]
    pub fn env_name(&self) -> Option<String> {
        let text = std::str::from_utf8(secrecy::ExposeSecret::expose_secret(&self.name)).ok()?;
        if !valid_name(&self.name) || envcloak_policy::value_shaped(text) {
            return None;
        }
        Some(text.to_owned())
    }
}
#[allow(clippy::disallowed_methods)] // Inspect a candidate name, never print it.
pub(super) fn valid_name(name: &SecretBytes) -> bool {
    std::str::from_utf8(secrecy::ExposeSecret::expose_secret(name))
        .ok()
        .is_some_and(|s| envcloak_policy::EnvName::new(s).is_ok())
}
