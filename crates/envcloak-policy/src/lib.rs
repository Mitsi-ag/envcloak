//! EnvCloak policy: project manifests, env files, bindings, project
//! identity and the effective policy (SPEC §5 "Project manifest", §6.1
//! steps 1 and 2, §10b). Caller evidence, grants and approvals join it in
//! later M1 tasks.
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
//!
//! The formats are in docs/MANIFEST.md.

mod bind;
mod effective;
mod envfile;
mod manifest;
mod names;
mod project;

pub use bind::{BindError, BindErrorKind, BoundBinding, bind_items};
pub use effective::{EffectivePolicy, SubjectKind, VaultProjectPolicy, effective_policy};
pub use envfile::{
    EnvFileError, EnvFileErrorKind, EnvFileRef, EnvFileRefs, MAX_ENV_FILE, PlainVar,
    REFERENCE_SCHEME, parse_env_file_refs,
};
pub use manifest::{
    AgentsPolicy, Manifest, ManifestError, ManifestErrorKind, ManifestPolicy, Mode, Origin,
    parse_manifest, resolve,
};
pub use names::{Binding, EnvName, ProfileName, Reference};
pub use project::{
    MANIFEST_NAME, Project, ProjectIdentity, find_manifest, load_project, project_identity,
};
