//! Login state machine and per-attempt submission budgets (`SPEC.md` §6.8,
//! M2 plan D-25, D-27, gates `b13` and `b16`, task `M2b-07`).
//!
//! - Identifies login fields from `autocomplete` tokens (`username`,
//!   `current-password`, `one-time-code`), input `type`s (`text`, `email`,
//!   `password`, `tel`), `name`/`id` attributes, and optional target hints.
//! - Fills credentials exclusively through `DOM.focus` + `Input.insertText` on
//!   the focused node, never constructing a JavaScript expression containing
//!   any secret value.
//! - Enforces the per-attempt submission budget: at most
//!   [`MAX_PASSWORD_SUBMISSIONS`] (`1`) password submission and at most
//!   [`MAX_CODE_SUBMISSIONS`] (`2`) TOTP code submissions per attempt.
//! - Detects handoff states (`CAPTCHA`, `data-handoff`, WebAuthn / security-key
//!   prompts, unexpected MFA challenges) and stops immediately with
//!   [`AttemptFailure::HandoffRequired`] (`D-27`).

use serde::{Deserialize, Serialize};

use envcloak_signin::AttemptFailure;

/// Maximum number of password submissions permitted in a single attempt (`b16`).
pub const MAX_PASSWORD_SUBMISSIONS: u8 = 1;

/// Maximum number of one-time code submissions permitted in a single attempt (`b16`).
pub const MAX_CODE_SUBMISSIONS: u8 = 2;

/// Optional per-target field selector hints.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginFieldHints {
    pub username_selector: Option<String>,
    pub password_selector: Option<String>,
    pub code_selector: Option<String>,
    pub submit_selector: Option<String>,
}

/// Snapshot of a form input element inspected from the DOM (never containing
/// any field value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectedInput {
    pub selector: String,
    pub id: String,
    pub name: String,
    pub input_type: String,
    pub autocomplete: String,
}

/// Snapshot of a page's login surface inspected without reading secret values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageLoginSurface {
    pub document_url: String,
    pub form_action: Option<String>,
    pub has_handoff_marker: bool,
    pub has_rejection_marker: bool,
    pub has_code_rejection_marker: bool,
    pub has_cross_origin_iframe: bool,
    pub cross_origin_iframe_src: Option<String>,
    pub inputs: Vec<InspectedInput>,
    pub submit_selector: Option<String>,
}

/// Next action decided by [`LoginStateMachine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginStepDecision {
    /// Fill username and password (and optional first TOTP code if on the same
    /// form) and submit.
    SubmitCredentials {
        username_selector: Option<String>,
        password_selector: String,
        code_selector: Option<String>,
        submit_selector: String,
    },
    /// Fill a TOTP code on a separate second-step form (`step` is `1` or `2`).
    SubmitCode {
        step: u8,
        code_selector: String,
        submit_selector: String,
    },
    /// The page has completed login (no login form or rejection present).
    Completed,
    /// Stop the attempt with the given [`AttemptFailure`].
    Stop(AttemptFailure),
}

/// Tracks per-attempt credential and code submission counts (`b16`) and decides
/// the next [`LoginStepDecision`] from a [`PageLoginSurface`].
#[derive(Debug, Clone, Default)]
pub struct LoginStateMachine {
    password_submissions: u8,
    code_submissions: u8,
    hints: LoginFieldHints,
}

impl LoginStateMachine {
    /// Creates a new [`LoginStateMachine`] with optional [`LoginFieldHints`].
    pub fn new(hints: LoginFieldHints) -> Self {
        Self {
            password_submissions: 0,
            code_submissions: 0,
            hints,
        }
    }

    /// Number of password submissions performed so far in this attempt.
    pub const fn password_submissions(&self) -> u8 {
        self.password_submissions
    }

    /// Number of code submissions performed so far in this attempt.
    pub const fn code_submissions(&self) -> u8 {
        self.code_submissions
    }

    /// Records that a password submission is about to be sent, enforcing
    /// [`MAX_PASSWORD_SUBMISSIONS`].
    ///
    /// # Errors
    /// Returns [`AttemptFailure::CredentialsRejected`] if the password budget is
    /// already exhausted.
    pub fn record_password_submission(&mut self) -> Result<u8, AttemptFailure> {
        if self.password_submissions >= MAX_PASSWORD_SUBMISSIONS {
            return Err(AttemptFailure::CredentialsRejected);
        }
        self.password_submissions += 1;
        Ok(self.password_submissions)
    }

    /// Records that a TOTP code submission is about to be sent, enforcing
    /// [`MAX_CODE_SUBMISSIONS`].
    ///
    /// # Errors
    /// Returns [`AttemptFailure::CodeRejected`] if the code budget (`2`) is
    /// already exhausted.
    pub fn record_code_submission(&mut self) -> Result<u8, AttemptFailure> {
        if self.code_submissions >= MAX_CODE_SUBMISSIONS {
            return Err(AttemptFailure::CodeRejected);
        }
        self.code_submissions += 1;
        Ok(self.code_submissions)
    }

    /// Evaluates `surface` and returns the next [`LoginStepDecision`].
    pub fn decide(&self, surface: &PageLoginSurface) -> LoginStepDecision {
        if surface.has_cross_origin_iframe {
            return LoginStepDecision::Stop(AttemptFailure::OffOrigin);
        }
        if surface.has_handoff_marker {
            return LoginStepDecision::Stop(AttemptFailure::HandoffRequired);
        }
        if surface.has_code_rejection_marker && self.code_submissions >= MAX_CODE_SUBMISSIONS {
            return LoginStepDecision::Stop(AttemptFailure::CodeRejected);
        }
        if surface.has_rejection_marker && self.password_submissions >= MAX_PASSWORD_SUBMISSIONS {
            return LoginStepDecision::Stop(AttemptFailure::CredentialsRejected);
        }

        let username_sel = self.find_username_selector(&surface.inputs);
        let password_sel = self.find_password_selector(&surface.inputs);
        let code_sel = self.find_code_selector(&surface.inputs);
        let submit_sel = self
            .hints
            .submit_selector
            .clone()
            .or_else(|| surface.submit_selector.clone())
            .unwrap_or_else(|| {
                "button[type=\"submit\"], input[type=\"submit\"], #submit".to_owned()
            });

        if let Some(pw_sel) = password_sel {
            if self.password_submissions >= MAX_PASSWORD_SUBMISSIONS {
                return LoginStepDecision::Stop(AttemptFailure::CredentialsRejected);
            }
            return LoginStepDecision::SubmitCredentials {
                username_selector: username_sel,
                password_selector: pw_sel,
                code_selector: code_sel,
                submit_selector: submit_sel,
            };
        }

        if let Some(c_sel) = code_sel {
            if self.code_submissions >= MAX_CODE_SUBMISSIONS {
                return LoginStepDecision::Stop(AttemptFailure::CodeRejected);
            }
            return LoginStepDecision::SubmitCode {
                step: self.code_submissions + 1,
                code_selector: c_sel,
                submit_selector: submit_sel,
            };
        }

        if surface.has_code_rejection_marker {
            return LoginStepDecision::Stop(AttemptFailure::CodeRejected);
        }
        if surface.has_rejection_marker {
            return LoginStepDecision::Stop(AttemptFailure::CredentialsRejected);
        }

        LoginStepDecision::Completed
    }

    fn find_username_selector(&self, inputs: &[InspectedInput]) -> Option<String> {
        if let Some(h) = &self.hints.username_selector {
            return Some(h.clone());
        }
        inputs
            .iter()
            .find(|inp| {
                inp.autocomplete
                    .split_whitespace()
                    .any(|t| t.eq_ignore_ascii_case("username") || t.eq_ignore_ascii_case("email"))
                    || inp.input_type.eq_ignore_ascii_case("email")
                    || inp.name.eq_ignore_ascii_case("username")
                    || inp.name.eq_ignore_ascii_case("email")
                    || inp.id.eq_ignore_ascii_case("username")
            })
            .map(|inp| inp.selector.clone())
    }

    fn find_password_selector(&self, inputs: &[InspectedInput]) -> Option<String> {
        if let Some(h) = &self.hints.password_selector {
            return Some(h.clone());
        }
        inputs
            .iter()
            .find(|inp| {
                inp.autocomplete
                    .split_whitespace()
                    .any(|t| t.eq_ignore_ascii_case("current-password"))
                    || inp.input_type.eq_ignore_ascii_case("password")
                    || inp.name.eq_ignore_ascii_case("password")
                    || inp.id.eq_ignore_ascii_case("password")
            })
            .map(|inp| inp.selector.clone())
    }

    fn find_code_selector(&self, inputs: &[InspectedInput]) -> Option<String> {
        if let Some(h) = &self.hints.code_selector {
            return Some(h.clone());
        }
        inputs
            .iter()
            .find(|inp| {
                inp.autocomplete
                    .split_whitespace()
                    .any(|t| t.eq_ignore_ascii_case("one-time-code"))
                    || inp.name.eq_ignore_ascii_case("totp")
                    || inp.name.eq_ignore_ascii_case("otp")
                    || inp.name.eq_ignore_ascii_case("code")
                    || inp.id.eq_ignore_ascii_case("totp")
                    || inp.id.eq_ignore_ascii_case("otp")
            })
            .map(|inp| inp.selector.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_caps_one_password_and_two_codes_and_stops_on_handoff() {
        let mut sm = LoginStateMachine::new(LoginFieldHints::default());

        let captcha_surface = PageLoginSurface {
            document_url: "http://acme.localhost/login/captcha".into(),
            has_handoff_marker: true,
            ..Default::default()
        };
        assert_eq!(
            sm.decide(&captcha_surface),
            LoginStepDecision::Stop(AttemptFailure::HandoffRequired)
        );

        let login_surface = PageLoginSurface {
            document_url: "http://acme.localhost/login".into(),
            inputs: vec![
                InspectedInput {
                    selector: "#username".into(),
                    id: "username".into(),
                    name: "username".into(),
                    input_type: "text".into(),
                    autocomplete: "username".into(),
                },
                InspectedInput {
                    selector: "#password".into(),
                    id: "password".into(),
                    name: "password".into(),
                    input_type: "password".into(),
                    autocomplete: "current-password".into(),
                },
            ],
            submit_selector: Some("#submit".into()),
            ..Default::default()
        };
        assert!(matches!(
            sm.decide(&login_surface),
            LoginStepDecision::SubmitCredentials { .. }
        ));
        assert_eq!(sm.record_password_submission(), Ok(1));
        // Second password submission on error page is refused!
        assert_eq!(
            sm.decide(&login_surface),
            LoginStepDecision::Stop(AttemptFailure::CredentialsRejected)
        );
        assert_eq!(
            sm.record_password_submission(),
            Err(AttemptFailure::CredentialsRejected)
        );

        let code_surface = PageLoginSurface {
            document_url: "http://acme.localhost/login/mfa".into(),
            inputs: vec![InspectedInput {
                selector: "#totp".into(),
                id: "totp".into(),
                name: "totp".into(),
                input_type: "text".into(),
                autocomplete: "one-time-code".into(),
            }],
            submit_selector: Some("#submit".into()),
            ..Default::default()
        };
        assert_eq!(
            sm.decide(&code_surface),
            LoginStepDecision::SubmitCode {
                step: 1,
                code_selector: "#totp".into(),
                submit_selector: "#submit".into()
            }
        );
        assert_eq!(sm.record_code_submission(), Ok(1));
        assert_eq!(
            sm.decide(&code_surface),
            LoginStepDecision::SubmitCode {
                step: 2,
                code_selector: "#totp".into(),
                submit_selector: "#submit".into()
            }
        );
        assert_eq!(sm.record_code_submission(), Ok(2));
        // Third code submission is refused!
        assert_eq!(
            sm.decide(&code_surface),
            LoginStepDecision::Stop(AttemptFailure::CodeRejected)
        );
        assert_eq!(
            sm.record_code_submission(),
            Err(AttemptFailure::CodeRejected)
        );
    }
}
