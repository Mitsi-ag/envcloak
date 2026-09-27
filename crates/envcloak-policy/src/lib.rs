//! EnvCloak policy: project manifests, env files, bindings and the
//! effective policy (SPEC §5 "Project manifest", §6.1 step 2, §10b).
//! Project identity, caller evidence, grants and approvals join it in later
//! M1 tasks.
//!
//! - [`parse_manifest`]: `envcloak.toml`, whose `[policy]` can only tighten.
//!   Errors are value-free: a [`ManifestErrorKind`] and an [`Origin`].
//! - [`parse_env_file_refs`]: `--env-file` files, parsed in place from
//!   [`envcloak_core::SecretBytes`]; errors carry a line and a kind only.
//! - [`resolve`]: the bindings a run asks for, from the manifest, a
//!   profile, `--ref` and `--env-file`.
//! - [`bind_items`]: bindings tied to the vault's secret items, refusing
//!   cards and issuer credentials.
//! - [`effective_policy`]: the vault's policy for the project tightened by
//!   the manifest's.

mod bind;
mod effective;
mod envfile;
mod manifest;
mod names;

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
