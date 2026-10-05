//! The parts of the `envcloak` command-line client that other EnvCloak
//! clients reuse (M2 plan D-02): the verified connection to the daemon
//! ([`connect`]), failures and their stable tokens ([`fail`]), the
//! rendering of the daemon's metadata views as text and JSON ([`render`]),
//! reading a secret from a person ([`tty`]), the `.gitignore` reading of
//! `init` and `import` ([`gitignore`]), the agent markers a process
//! carries ([`claims`]), the manifest editor of `envcloak ref`
//! ([`manifest_edit`]) and the status record `envcloak run --status-fd`
//! writes for `envcloak mcp` ([`run_status`]).
//!
//! The `envcloak` binary keeps argument parsing and printing. `envcloak
//! mcp` and the agent installers build on this crate rather than on the
//! binary: the binary depends on `envcloak-mcp` for `envcloak mcp`, so a
//! library target inside it would be a package cycle. This crate's own
//! dependencies stay within `envcloak-core`, `envcloak-ipc`,
//! `envcloak-policy`, `envcloak-providers` and `envcloak-sys`
//! (`scripts/check-crate-graph.py`).
//!
//! Nothing here holds the vault key, takes a value as an argument or
//! echoes one: the rules of the modules are the CLI's (SPEC §4.4, §5,
//! gate 13). The names below are the M2 plan's for the M1 items they
//! stand for.

pub mod claims;
pub mod connect;
pub mod doctor_report;
pub mod fail;
pub mod gitignore;
pub mod managed;
pub mod manifest_edit;
pub mod render;
pub mod run_status;
pub mod tty;

pub use claims::{claims, refuse_if_claimed};
/// The daemon connection, verified before anything is sent.
pub use connect::connect as connect_verified;
/// A failure to report: a stable token and a fixed message.
pub use fail::{ExitToken, Failure as Fail};
pub use manifest_edit::edit_manifest_ref;
pub use render::Render;
/// The controlling terminal, read with echo off.
pub use tty::Terminal as SecretPrompt;
