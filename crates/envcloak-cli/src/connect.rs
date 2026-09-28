//! The CLI's connection to the daemon (SPEC §4.1, §4.2): verified before
//! anything is sent, and never a daemon the CLI started. When none
//! answers, the CLI says how to start one and does nothing else; it never
//! looks for `envcloakd` on `PATH`.

use envcloak_ipc::{Client, ClientError, RunPaths};

use crate::fail::Failure;

/// The runtime paths for this user, from `HOME` and the XDG variables.
pub fn run_paths() -> Result<RunPaths, Failure> {
    RunPaths::for_user().map_err(|e| Failure::from(ClientError::Paths(e.kind())))
}

/// Connects to this user's daemon and verifies it.
pub fn connect() -> Result<Client, Failure> {
    let paths = run_paths()?;
    Client::connect(&paths).map_err(Failure::from)
}
