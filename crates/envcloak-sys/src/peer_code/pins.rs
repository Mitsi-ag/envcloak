//! Build-time identity pins. Forks may change the identifiers here.
//! Source builds pin nothing. Signed builds set TEAM_ID here before compiling;
//! no process environment or request can disable an embedded pin.

use super::{PeerCodeError, PinnedRequirement};

pub const APP_IDENTIFIER: &str = "ai.envcloak.app";
pub const AGENT_IDENTIFIER: &str = "ai.envcloak.agent";
pub const CLI_IDENTIFIER: &str = "ai.envcloak.cli";
pub const TEAM_ID: Option<&str> = None;

// The native test runner substitutes its disposable certificate fingerprint,
// builds with testing, then restores this file byte for byte. Never shipped.
#[cfg(all(feature = "testing", debug_assertions))]
const CI_CERT_SHA1: Option<&str> = None;

pub fn app() -> Result<Option<PinnedRequirement>, PeerCodeError> {
    requirement(APP_IDENTIFIER)
}

pub fn agent() -> Result<Option<PinnedRequirement>, PeerCodeError> {
    requirement(AGENT_IDENTIFIER)
}

fn requirement(identifier: &str) -> Result<Option<PinnedRequirement>, PeerCodeError> {
    if !cfg!(target_os = "macos") {
        return Ok(None);
    }
    #[cfg(all(feature = "testing", debug_assertions))]
    if let Some(hash) = CI_CERT_SHA1 {
        if hash.len() != 40 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PeerCodeError::Configuration);
        }
        return Ok(Some(PinnedRequirement(format!(
            "identifier \"{identifier}\" and certificate leaf = H\"{hash}\""
        ))));
    }
    match TEAM_ID {
        None => Ok(None),
        Some(team)
            if team.len() == 10
                && team
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) =>
        {
            Ok(Some(PinnedRequirement(format!(
                "identifier \"{identifier}\" and anchor apple generic and certificate leaf[subject.OU] = \"{team}\""
            ))))
        }
        Some(_) => Err(PeerCodeError::Configuration),
    }
}
