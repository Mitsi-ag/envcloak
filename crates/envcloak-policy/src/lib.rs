//! EnvCloak policy: project manifests, env files, bindings, project
//! identity, caller evidence, the effective policy, and grants with their
//! approvals (SPEC §5 "Project manifest", §6.1 steps 1 to 4, §10a, §10b).
//!
//! - [`parse_manifest`]: `envcloak.toml`, whose `[policy]` can only tighten.
//!   Errors are value-free: a [`ManifestErrorKind`] and an [`Origin`].
//! - [`parse_env_file_refs`]: `--env-file` files, parsed in place from
//!   [`envcloak_core::SecretBytes`]; errors carry a line and a kind only.
//! - [`resolve`]: the bindings a run asks for, from the manifest, a
//!   profile, `--ref` and `--env-file`.
//! - [`bind_items`]: bindings tied to the vault's secret items, refusing
//!   cards and issuer credentials.
//! - [`find_manifest`], [`project_identity`] and [`load_project`]: the
//!   project a manifest belongs to, from the opened directory's device and
//!   inode and its canonical path.
//! - [`effective_policy`]: the vault's policy for the project tightened by
//!   the manifest's.
//! - [`AgentCatalog`]: the known agents, builtin (`integrations/agents.toml`)
//!   and the user's add-only extensions; docs/AGENTS.md.
//! - [`gather`]: a caller's evidence from the kernel's view of its
//!   ancestry, its agents and its claims: the grant root, the subject's
//!   kind, and whether a grant may cover it ([`SubjectEvidence`]).
//! - [`GrantStore`]: grants, pending requests and the decision for a
//!   request (SPEC §10b), with the pending caps and denial rules of
//!   SPEC §10a "Bounds" ([`flood`]) and the passphrase attempt limiter
//!   ([`AttemptLimiter`]). The store holds no value and is never written
//!   to disk.
//! - [`PendingDescriptor`], [`canonical_statement`] and
//!   [`render_statement`]: what an approval surface shows for a pending
//!   request, and the bytes the proof approves.
//!
//! The formats are in docs/MANIFEST.md and docs/GRANTS.md.

mod agents;
mod agents_builtin;
mod bind;
mod effective;
mod envfile;
mod evidence;
pub mod flood;
mod grants;
mod ids;
mod limiter;
mod manifest;
mod names;
mod pending;
mod project;
mod statement;

pub use agents::{
    AGENTS_DIR, AgentCatalog, AgentLabel, CatalogError, CatalogErrorKind, CatalogProblem,
    CatalogSource, MAX_CATALOG_FILE, MAX_EXTENSION_FILES, MatchBasis,
};
pub use bind::{BindError, BindErrorKind, BoundBinding, bind_items};
pub use effective::{EffectivePolicy, SubjectKind, VaultProjectPolicy, effective_policy};
pub use envfile::{
    EnvFileError, EnvFileErrorKind, EnvFileNames, EnvFileRef, EnvFileRefs, MAX_ENV_FILE, PlainName,
    PlainVar, REFERENCE_SCHEME, parse_env_file_refs,
};
pub use evidence::{
    Ancestor, ChainEnd, Claims, ClaimsError, EvidenceError, GATHER_ATTEMPTS, ProcessInstance,
    ProofRefusal, SubjectEvidence, gather, gather_in,
};
pub use flood::{
    AUTO_DENY, DENIAL_WINDOW, DENIALS_TO_AUTO_DENY, MAX_DENIALS, MAX_PENDING, MAX_PENDING_PER_ROOT,
};
pub use grants::{
    AccessRequest, ApprovalOptions, ApprovalProof, ApproveError, BoundRef, DEFAULT_TTL, Decision,
    DenyOutcome, DenyReason, Grant, GrantBinding, GrantId, GrantStore, MAX_AGENT_TTL, MAX_GRANTS,
    MAX_TERMINAL_TTL, NoSuchRequest, Now, OptionsError, ProofKind, RevokeSelector, Uses,
};
pub use limiter::{AttemptLimiter, FIRST_WAIT, FREE_ATTEMPTS, MAX_WAIT};
pub use manifest::{
    AgentsPolicy, Manifest, ManifestError, ManifestErrorKind, ManifestPolicy, Mode, Origin,
    parse_manifest, resolve,
};
pub use names::{Binding, EnvName, ProfileName, Reference, VALUE_RUN, value_shaped};
pub use pending::{PENDING_TTL, Pending, PendingId};
pub use project::{
    MANIFEST_NAME, Project, ProjectIdentity, find_manifest, load_project, project_identity,
};
pub use statement::{
    BindingSummary, PendingDescriptor, ProcessSummary, ProjectSummary, RENDER_LIMIT,
    SubjectSummary, canonical_statement, display_escaped, escape_for_display, render_statement,
    statement_digest,
};
