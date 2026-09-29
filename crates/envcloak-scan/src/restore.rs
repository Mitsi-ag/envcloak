//! Writing an env file's bytes (SPEC §6.4): back from its encrypted backup
//! (`envcloak init --undo` restores the original byte for byte), and with
//! the entries the vault holds taken out (`envcloak init
//! --delete-plaintext`).
//!
//! The one place this crate writes a secret:
//! - [`restore_file`] creates the file as [`crate::create_atomically`] does
//!   (a new file beside it, flushed, linked into place only if the name is
//!   free), from the bytes the daemon handed back after a proof. It never
//!   replaces a file: one that exists stays as it is.
//! - [`restore_over`] puts the original back over the file a deletion
//!   rewrote, as [`crate::replace_atomically`] replaces one, only while it
//!   is still the file read (the caller checked it is that rewrite,
//!   [`crate::trimmed_from`]).
//! - [`rewrite_observed`] rewrites a file under the rules of a removal
//!   ([`crate::rewrite_checked`]) to hold what the vault does not.

use std::path::Path;

use envcloak_core::SecretBytes;
use secrecy::ExposeSecret;

use std::time::SystemTime;

use crate::atomic::{
    Inside, ModifyError, create_atomically, replace_atomically, rewrite_checked_observed,
};
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

/// Replaces the file at `rel` under `r`, which must still be the one
/// `expect` stamps, with `content`, keeping its mode. Returns the new
/// file's stamp.
///
/// # Errors
/// As [`replace_atomically`].
pub fn restore_over(
    r: &ScanRoot,
    rel: &Path,
    content: &SecretBytes,
    expect: &FileStamp,
) -> Result<FileStamp, ModifyError> {
    #[allow(clippy::disallowed_methods)] // Writes the file back, as the person asked, with a proof.
    let bytes = content.expose_secret();
    replace_atomically(r, rel, bytes, expect)
}

/// Rewrites the file at `rel` under `r` to `content`, at the time `now`,
/// under the rules of a removal, telling `observe` when the new contents
/// are staged. Returns the new file's stamp.
///
/// # Errors
/// As [`crate::rewrite_checked`].
pub fn rewrite_observed(
    r: &ScanRoot,
    rel: &Path,
    content: &SecretBytes,
    expect: &FileStamp,
    now: SystemTime,
    observe: &mut dyn FnMut(Inside),
) -> Result<FileStamp, ModifyError> {
    #[allow(clippy::disallowed_methods)]
    // What the file keeps: the entries the vault does not hold.
    let bytes = content.expose_secret();
    rewrite_checked_observed(r, rel, bytes, expect, now, observe)
}
