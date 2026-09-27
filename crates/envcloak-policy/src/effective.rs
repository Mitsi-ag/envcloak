//! The policy a request is handled under: the vault's policy for the
//! project, tightened by the manifest's `[policy]` and never loosened
//! (SPEC §5 "Project manifest", gate 17).
//!
//! Loosening settings live only in the vault and change only with an
//! approval proof (SPEC §10b). The manifest is repo content an agent can
//! edit, so each of its settings can only move a decision toward the
//! stricter side:
//! - `agents = "deny"` refuses agent requests; `"allow"` does not parse.
//! - `redact = true` turns redaction on; `false` changes nothing. Agent
//!   subjects, and subjects of unknown kind, are always redacted.
//! - `mode = "proxy"` makes proxy mode required; `"inject"` changes
//!   nothing. In M1, which has no proxy (SPEC §14), a proxy-mode request is
//!   refused rather than injected.

use crate::manifest::{AgentsPolicy, ManifestPolicy, Mode};

/// The vault's policy for one project. The defaults are the strictest
/// settings that still let a request be approved: agents need approval,
/// output is redacted, values are injected (the only mode in M1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VaultProjectPolicy {
    pub agents: AgentsPolicy,
    /// Whether output is redacted for a terminal subject. Agent subjects
    /// and subjects of unknown kind are redacted whatever this says.
    pub redact: bool,
    pub mode: Mode,
}

impl Default for VaultProjectPolicy {
    fn default() -> Self {
        VaultProjectPolicy {
            agents: AgentsPolicy::Approve,
            redact: true,
            mode: Mode::Inject,
        }
    }
}

/// Who a request is for, as the daemon classified its caller (SPEC §10a,
/// §10b `subject.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectKind {
    /// A known agent is in the caller's ancestry, or the caller claims to
    /// be one.
    Agent,
    /// No agent was found and the root is the caller's session leader.
    /// This never proves a human is present; it only means nothing says
    /// otherwise.
    Terminal,
    /// The ancestry could not be established. Handled as strictly as an
    /// agent.
    Unknown,
}

/// The policy a request is handled under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EffectivePolicy {
    /// Refuse the request outright, without opening a pending request.
    pub deny: bool,
    /// Redact the command's output.
    pub redact: bool,
    /// The strictest mode of the vault's and the manifest's.
    pub mode: Mode,
}

/// Combines the vault's policy for the project with the manifest's
/// `[policy]` for a subject. Every field of the result is at least as
/// strict as the vault's policy alone gives, and at least as strict as
/// each tightening the manifest asks for.
pub fn effective_policy(
    vault: &VaultProjectPolicy,
    m: &ManifestPolicy,
    s: SubjectKind,
) -> EffectivePolicy {
    let agent_like = s != SubjectKind::Terminal;
    let agents = vault.agents.max(m.agents);
    EffectivePolicy {
        deny: agent_like && agents == AgentsPolicy::Deny,
        redact: agent_like || vault.redact || m.redact == Some(true),
        mode: vault.mode.max(m.mode.unwrap_or(Mode::Inject)),
    }
}
