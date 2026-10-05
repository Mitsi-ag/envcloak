//! Filesystem-safe scanning, dotenv parsing and atomic file changes (SPEC
//! §6.4), for `envcloak init` and `envcloak import`, and later doctor and
//! scrub.
//!
//! Scanning runs in the CLI, never in the daemon or the app, so a macOS
//! privacy prompt names the terminal the person runs it in. The CLI sends
//! what it found to a verified daemon, which alone holds the key to match
//! values and seal them.
//!
//! - [`root`]: [`open_root`] and [`ScanRoot`], the directory a scan starts
//!   from, held open; [`read_capped`], one file read whole into a wiped
//!   buffer with its [`FileStamp`].
//! - [`walk`]: [`walk_dotenv`], the `.env` files below a root, never
//!   through a symlink, across a mount point or into a FIFO.
//! - [`dotenv`]: [`parse_dotenv`], a value-free-error parser that never
//!   expands a variable.
//! - [`atomic`]: [`replace_atomically`], [`create_atomically`],
//!   [`remove_checked`] and [`rewrite_checked`], which act only on the
//!   file that was read.
//! - [`delete`]: [`delete_plaintext`], the entries the vault holds taken
//!   out of their files after the four conditions of gate 16; [`restore`]:
//!   [`restore_file`] and [`restore_over`], a file written back from its
//!   encrypted backup, [`restore_over_left`], one written back from a
//!   backup v2 only while it is what the change left, and
//!   [`rewrite_observed`], a file rewritten to hold what the vault does
//!   not.
//! - [`pause_point`]: the points gate 16's test kills `envcloak init` at,
//!   which do nothing outside a test build.
//! - [`source`]: [`source::ConfigSource`], the neutral descriptor of a
//!   config or store to scan, which the agent catalog emits (M2 plan D-02).
//!
//! Nothing here logs, and no error carries text from a file.

pub mod agent_config;
pub mod git;
pub mod sources;
pub use agent_config::scan_config_sources;
pub mod atomic;
pub mod candidates;
pub mod delete;
pub mod dotenv;
mod json;
pub mod profile;
pub mod restore;
pub mod root;
pub mod source;
pub mod transcript;
pub mod walk;

#[cfg(feature = "testing")]
pub mod testing;

pub use atomic::{
    Inside, MIN_AGE, ModifyError, ModifyErrorKind, create_atomically, remove_checked,
    remove_checked_at, remove_checked_observed, replace_atomically, rewrite_checked,
    rewrite_checked_observed,
};
pub use delete::{DeleteGate, DeleteOutcome, DeleteStep, Remains, delete_plaintext};
pub use dotenv::{
    DotenvEntry, DotenvError, DotenvErrorKind, EntryKind, MAX_DOTENV, parse_dotenv, trimmed_from,
    without_entries,
};
pub use restore::{
    BackedUpFile, restore_file, restore_over, restore_over_left, restore_over_left_observed,
    restore_over_observed, rewrite_observed,
};
pub use root::{FileStamp, ScanError, ScanErrorKind, ScanRoot, open_root, read_capped, read_plain};
pub use walk::{
    DEFAULT_SKIP_DIRS, FileKind, FoundFile, TEMPLATE_SUFFIXES, Walk, WalkOptions, dotenv_kind,
    leftover_name, walk_dotenv,
};

/// A point `envcloak init` passes while it imports and deletes plaintext,
/// named for gate 16's test, which kills the process at each. Nothing in a
/// build without the `testing` feature, which only tests enable (release
/// builds never have it: `crates/envcloak-cli/tests/release_features.rs`).
/// With it, and `ENVCLOAK_TEST_PAUSE_DIR` set, the process says where it
/// is in that directory and waits to be told to go on.
pub fn pause_point(name: &str) {
    #[cfg(feature = "testing")]
    testing::pause(name);
    #[cfg(not(feature = "testing"))]
    let _ = name;
}
