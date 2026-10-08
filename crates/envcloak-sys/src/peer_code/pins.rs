//! Build-time identity pins. Forks may change the identifiers here.
//! Source builds pin nothing. Signed builds set TEAM_ID here before compiling;
//! no process environment or request can disable an embedded pin.

use super::{PeerCodeError, PinnedRequirement};

pub const APP_IDENTIFIER: &str = "ai.envcloak.app";
pub const AGENT_IDENTIFIER: &str = "ai.envcloak.agent";
pub const CLI_IDENTIFIER: &str = "ai.envcloak.cli";
pub const TEAM_ID: Option<&str> = None;

// build.rs validates this public test certificate fingerprint and refuses all
// testing-feature release builds, including ones with debug assertions enabled.
#[cfg(feature = "testing")]
const CI_CERT_SHA1: &str = env!("ENVCLOAK_COMPILED_TEST_CERT");

pub fn app() -> Result<Option<PinnedRequirement>, PeerCodeError> {
    requirement(APP_IDENTIFIER)
}

pub fn agent() -> Result<Option<PinnedRequirement>, PeerCodeError> {
    requirement(AGENT_IDENTIFIER)
}

fn requirement(identifier: &str) -> Result<Option<PinnedRequirement>, PeerCodeError> {
    // Keep a test-support marker in binaries even when no fixture pin was
    // supplied. The artifact signing checker refuses it in every signing tier.
    #[cfg(feature = "testing")]
    std::hint::black_box("ENVCLOAK_TEST_CERT_SHA1");
    if !cfg!(target_os = "macos") {
        return Ok(None);
    }
    #[cfg(feature = "testing")]
    if !CI_CERT_SHA1.is_empty() {
        let hash = CI_CERT_SHA1;
        if hash.len() != 40 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PeerCodeError::Configuration);
        }
        return Ok(Some(PinnedRequirement(format!(
            "identifier \"{identifier}\" and certificate leaf = H\"{hash}\""
        ))));
    }
    production_requirement(identifier, TEAM_ID)
}

fn production_requirement(
    identifier: &str,
    team: Option<&str>,
) -> Result<Option<PinnedRequirement>, PeerCodeError> {
    match team {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_test_pin_tracks_the_current_build_input() {
        assert_eq!(
            CI_CERT_SHA1,
            std::env::var("ENVCLOAK_TEST_CERT_SHA1").unwrap_or_default()
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn production_requirements_compile_with_security_framework() {
        use security_framework::os::macos::code_signing::SecRequirement;
        for identifier in [APP_IDENTIFIER, AGENT_IDENTIFIER, CLI_IDENTIFIER] {
            let requirement = production_requirement(identifier, Some("AB12CD34EF"))
                .expect("valid test Team ID")
                .expect("pinned requirement");
            let parsed: Result<SecRequirement, _> = requirement.0.parse();
            assert!(
                parsed.is_ok(),
                "Security.framework rejected the production syntax"
            );
        }
    }

    #[test]
    fn production_team_ids_fail_closed() {
        assert!(matches!(
            production_requirement(APP_IDENTIFIER, None),
            Ok(None)
        ));
        for team in [
            "",
            "AB12CD34E",
            "AB12CD34EFG",
            "ab12cd34ef",
            "ééééé",
            "AB12CD34E\n",
            "\" or true",
        ] {
            assert!(matches!(
                production_requirement(APP_IDENTIFIER, Some(team)),
                Err(PeerCodeError::Configuration)
            ));
        }
    }
}
