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
//! - [`atomic`]: [`replace_atomically`], [`create_atomically`] and
//!   [`remove_checked`], which act only on the file that was read.
//! - [`delete`]: [`delete_plaintext`], removal after the four conditions
//!   of gate 16; [`restore`]: [`restore_file`], a file written back from
//!   its encrypted backup.
//!
//! Nothing here logs, and no error carries text from a file.

pub mod atomic;
pub mod delete;
pub mod dotenv;
pub mod restore;
pub mod root;
pub mod walk;

pub use atomic::{
    MIN_AGE, ModifyError, ModifyErrorKind, create_atomically, remove_checked, remove_checked_at,
    replace_atomically,
};
pub use delete::{DeleteGate, DeleteOutcome, DeleteStep, delete_plaintext};
pub use dotenv::{DotenvEntry, DotenvError, DotenvErrorKind, EntryKind, MAX_DOTENV, parse_dotenv};
pub use restore::restore_file;
pub use root::{FileStamp, ScanError, ScanErrorKind, ScanRoot, open_root, read_capped, read_plain};
pub use walk::{
    DEFAULT_SKIP_DIRS, FileKind, FoundFile, TEMPLATE_SUFFIXES, Walk, WalkOptions, dotenv_kind,
    walk_dotenv,
};
