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
//!   ([`AttemptLimiter`]), and how a request stands for the process tree
//!   that waits on it ([`PendingState`], `GrantStore::poll`). The store
//!   holds no value and is never written to disk.
//! - [`managed`]: managed MCP servers' launch declarations, their argv
//!   classes, updates, the server's environment, the update statement and
//!   the launch receipt's sentences (SPEC §6.6, M2 task M2-27).
//! - [`PendingDescriptor`], [`canonical_statement`] and
//!   [`render_statement`]: what an approval surface shows for a pending
//!   request, and the bytes the proof approves; the live-key guard
//!   ([`unticked_live`]) and the test items proposed for live bindings
//!   ([`proposals`]).
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
pub mod managed;
mod manifest;
mod names;
mod pending;
mod project;
mod statement;

pub use agents::{
    AGENTS_DIR, AgentCatalog, AgentLabel, CatalogError, CatalogErrorKind, CatalogProblem,
    CatalogSource, ExtensionFiles, LOADER_ENV_PREFIXES, MAX_CATALOG_FILE, MAX_EXTENSION_FILES,
    MatchBasis,
};
pub use bind::{BindError, BindErrorKind, BoundBinding, bind_items};
pub use effective::{EffectivePolicy, SubjectKind, VaultProjectPolicy, effective_policy};
pub use envfile::{
    EnvFileError, EnvFileErrorKind, EnvFileNames, EnvFileRef, EnvFileRefs, MAX_ENV_FILE, PlainName,
    PlainVar, REFERENCE_SCHEME, parse_env_file_refs,
};
pub use evidence::{
    Ancestor, ChainEnd, Claims, ClaimsError, EvidenceError, ExeDigest, ExeHasher, GATHER_ATTEMPTS,
    ProcessInstance, ProofRefusal, SubjectEvidence, gather, gather_hashed, gather_in,
    gather_in_hashed,
};
pub use flood::{
    AUTO_DENY, DENIAL_WINDOW, DENIALS_TO_AUTO_DENY, MAX_DENIALS, MAX_PENDING, MAX_PENDING_PER_ROOT,
};
pub use grants::{
    AccessRequest, ApprovalOptions, ApprovalProof, ApproveError, BoundRef, DEFAULT_TTL, Decision,
    DenyOutcome, DenyReason, Grant, GrantBinding, GrantId, GrantStore, MAX_AGENT_TTL, MAX_GRANTS,
    MAX_TERMINAL_TTL, ManagedRequest, NoSuchRequest, Now, OptionsError, PendingCap, ProofKind,
    RevokeSelector, Uses,
};
pub use limiter::{AttemptLimiter, FIRST_WAIT, FREE_ATTEMPTS, MAX_WAIT};
pub use manifest::{
    AgentsPolicy, BindingSource, Manifest, ManifestError, ManifestErrorKind, ManifestPolicy, Mode,
    Origin, parse_manifest, resolve, resolve_sourced,
};
pub use names::{Binding, EnvName, ProfileName, Reference, VALUE_RUN, value_shaped};
pub use pending::{
    Busy, MAX_OUTCOMES, MAX_POLL_ROOTS, OUTCOME_TTL, PENDING_TTL, POLLS_PER_REQUEST, Pending,
    PendingId, PendingState,
};
pub use project::{
    MANIFEST_NAME, Project, ProjectIdentity, find_manifest, load_project, project_identity,
};
pub use statement::{
    BindingSummary, HIDDEN, ManagedSummary, PendingDescriptor, ProcessSummary, ProjectSummary,
    Proposal, RENDER_LIMIT, STATEMENT_DOMAIN, SubjectSummary, canonical_statement, display_escaped,
    escape_for_display, live_guarded, proposals, proposed_for, render_statement,
    render_statement_with, shell_word, shown_name, statement_digest, unticked_live,
};
