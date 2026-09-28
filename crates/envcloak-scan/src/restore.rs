//! Writing a file back from its encrypted backup (SPEC §6.4: `envcloak
//! init --undo` restores the original byte for byte).
//!
//! The one place this crate writes a secret: [`restore_file`] creates the
//! file as [`crate::create_atomically`] does (a new file beside it,
//! flushed, linked into place only if the name is free), from the bytes
//! the daemon handed back after a proof. It never replaces a file: one
//! that exists stays as it is.

use std::path::Path;

use envcloak_core::SecretBytes;
use secrecy::ExposeSecret;

use crate::atomic::{ModifyError, create_atomically};
use crate::root::{FileStamp, ScanRoot};

/// Creates the file at `rel` under `r` with `content` and `mode`, only if
/// no file has that name. Returns the new file's stamp.
///
/// # Errors
/// As [`create_atomically`]: [`crate::ModifyErrorKind::Exists`] when the
/// name is taken, a symlink in its place included.
pub fn restore_file(
    r: &ScanRoot,
    rel: &Path,
    content: &SecretBytes,
    mode: u32,
) -> Result<FileStamp, ModifyError> {
    #[allow(clippy::disallowed_methods)] // Writes the file back, as the person asked, with a proof.
    let bytes = content.expose_secret();
    create_atomically(r, rel, bytes, mode)
}
