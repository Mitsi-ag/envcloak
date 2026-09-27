//! EnvCloak policy: project manifests, env files and bindings (SPEC §5
//! "Project manifest", §6.1 step 2). Project identity, the effective
//! policy, caller evidence, grants and approvals join it in later M1 tasks.
//!
//! - [`parse_manifest`]: `envcloak.toml`, whose `[policy]` can only tighten.
//!   Errors are value-free: a [`ManifestErrorKind`] and an [`Origin`].
//! - [`parse_env_file_refs`]: `--env-file` files, parsed in place from
//!   [`envcloak_core::SecretBytes`]; errors carry a line and a kind only.
//! - [`resolve`]: the bindings a run asks for, from the manifest, a
//!   profile, `--ref` and `--env-file`.

mod envfile;
mod manifest;
mod names;

pub use envfile::{
    EnvFileError, EnvFileErrorKind, EnvFileRef, EnvFileRefs, MAX_ENV_FILE, PlainVar,
    REFERENCE_SCHEME, parse_env_file_refs,
};
pub use manifest::{
    AgentsPolicy, Manifest, ManifestError, ManifestErrorKind, ManifestPolicy, Mode, Origin,
    parse_manifest, resolve,
};
pub use names::{Binding, EnvName, ProfileName, Reference};
