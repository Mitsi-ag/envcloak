//! EnvCloak policy: project manifests, env files, bindings, project
//! identity, caller evidence and the effective policy (SPEC §5 "Project
//! manifest", §6.1 steps 1 to 3, §10a, §10b). Grants and approvals join it
//! in later M1 tasks.
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
//!
//! The formats are in docs/MANIFEST.md.

mod agents;
mod agents_builtin;
mod bind;
mod effective;
mod envfile;
mod evidence;
mod manifest;
mod names;
mod project;

pub use agents::{
    AGENTS_DIR, AgentCatalog, AgentLabel, CatalogError, CatalogErrorKind, CatalogProblem,
    CatalogSource, MAX_CATALOG_FILE, MAX_EXTENSION_FILES,
};
pub use bind::{BindError, BindErrorKind, BoundBinding, bind_items};
pub use effective::{EffectivePolicy, SubjectKind, VaultProjectPolicy, effective_policy};
pub use envfile::{
    EnvFileError, EnvFileErrorKind, EnvFileRef, EnvFileRefs, MAX_ENV_FILE, PlainVar,
    REFERENCE_SCHEME, parse_env_file_refs,
};
pub use evidence::{
    Ancestor, ChainEnd, Claims, ClaimsError, EvidenceError, GATHER_ATTEMPTS, ProcessInstance,
    SubjectEvidence, gather, gather_in,
};
pub use manifest::{
    AgentsPolicy, Manifest, ManifestError, ManifestErrorKind, ManifestPolicy, Mode, Origin,
    parse_manifest, resolve,
};
pub use names::{Binding, EnvName, ProfileName, Reference};
pub use project::{
    MANIFEST_NAME, Project, ProjectIdentity, find_manifest, load_project, project_identity,
};
