//! Deleting plaintext env files after import (SPEC §6.4 "Deleting
//! plaintext after import", gate 16).
//!
//! [`delete_plaintext`] removes files only after all four conditions hold,
//! and in this order:
//! 1. [`DeleteGate::verify`]: the vault write is committed and fsynced
//!    (every value the files hold is in the vault and bound where the
//!    manifest says), a dry run resolves every reference, and the Recovery
//!    Kit is confirmed;
//! 2. [`DeleteGate::backup`]: an encrypted backup of the files exists;
//! 3. [`DeleteGate::verify`] again, now, since the vault may have changed
//!    while the backup was written;
//! 4. each file is removed with [`crate::remove_checked`], which refuses a
//!    file that is not the one read, was modified in the last two minutes,
//!    or is open elsewhere.
//!
//! The daemon answers the gate: it holds the vault, and the CLI has no key
//! to check anything with. A crash at any point leaves each file in place,
//! or removed after its values were committed: nothing is removed before
//! step 3 has passed.

use std::path::PathBuf;

use crate::atomic::{ModifyErrorKind, remove_checked};
use crate::root::{FileStamp, ScanRoot};

/// What decides whether plaintext may be deleted.
pub trait DeleteGate {
    /// Why the gate refused.
    type Refusal;

    /// Conditions 1, 2 and 4: the files' values are committed and bound,
    /// every reference resolves, and the Recovery Kit is confirmed.
    ///
    /// # Errors
    /// The refusal, when any of them does not hold.
    fn verify(&mut self) -> Result<(), Self::Refusal>;

    /// Condition 3: writes the encrypted backup of the files, and returns
    /// its id once it is on disk.
    ///
    /// # Errors
    /// The refusal, when the backup could not be written.
    fn backup(&mut self) -> Result<String, Self::Refusal>;
}

/// The points [`delete_plaintext`] passes, in order. Tests stop it at each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeleteStep {
    Verified,
    BackedUp,
    Reverified,
    /// The file at this index was removed.
    Removed(usize),
}

/// What [`delete_plaintext`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteOutcome {
    /// The encrypted backup's id.
    pub backup: String,
    pub removed: Vec<PathBuf>,
    /// Files left in place, and why.
    pub kept: Vec<(PathBuf, ModifyErrorKind)>,
}

/// Removes `files` (paths under `r` with the stamps they were read with)
/// once `gate` allows it. See the module documentation.
///
/// # Errors
/// The gate's refusal; then nothing was removed.
pub fn delete_plaintext<G: DeleteGate>(
    r: &ScanRoot,
    files: &[(PathBuf, FileStamp)],
    gate: &mut G,
    observe: &mut dyn FnMut(DeleteStep),
) -> Result<DeleteOutcome, G::Refusal> {
    gate.verify()?;
    observe(DeleteStep::Verified);
    let backup = gate.backup()?;
    observe(DeleteStep::BackedUp);
    gate.verify()?;
    observe(DeleteStep::Reverified);
    let mut out = DeleteOutcome {
        backup,
        removed: Vec::new(),
        kept: Vec::new(),
    };
    for (i, (rel, stamp)) in files.iter().enumerate() {
        match remove_checked(r, rel, stamp) {
            Ok(()) => {
                out.removed.push(rel.clone());
                observe(DeleteStep::Removed(i));
            }
            Err(e) => out.kept.push((e.rel, e.kind)),
        }
    }
    Ok(out)
}
