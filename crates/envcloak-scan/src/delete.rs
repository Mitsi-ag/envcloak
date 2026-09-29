//! Deleting plaintext env files after import (SPEC §6.4 "Deleting
//! plaintext after import", gate 16).
//!
//! [`delete_plaintext`] changes files only after all four conditions hold,
//! and in this order:
//! 1. [`DeleteGate::verify`]: the vault write is committed and fsynced
//!    (every secret the files hold is in the vault and bound where the
//!    manifest says), a dry run resolves every reference, and the Recovery
//!    Kit is confirmed. Its answer also says which entries of each file
//!    the vault holds ([`DeleteGate::remains`]);
//! 2. [`DeleteGate::backup`]: an encrypted backup of the files to change
//!    exists;
//! 3. [`DeleteGate::verify`] again, now, since the vault may have changed
//!    while the backup was written: it must give the first answer;
//! 4. each file is changed with [`crate::remove_checked`] or
//!    [`crate::rewrite_checked`], which refuse a file that is not the one
//!    read, was modified in the last two minutes, or is open elsewhere.
//!
//! Only the entries the vault holds leave a file. A file whose every entry
//! the vault holds is removed; one that also holds entries the vault does
//! not (configuration, an interpolated value, a reference, a value the
//! daemon would not match) is rewritten to hold those, as they were; one
//! whose entries the vault holds none of is left as it is, and not backed
//! up.
//!
//! The daemon answers the gate: it holds the vault, and the CLI has no key
//! to check anything with. A crash at any point leaves each entry in its
//! file or committed in the vault: nothing is changed before step 3 has
//! passed, a rewrite swaps a whole new file in for the old one, and a
//! removal renames the file aside before it unlinks it (a crash between
//! the steps leaves one under a temporary name the scan reports).

use std::path::PathBuf;
use std::time::SystemTime;

use envcloak_core::SecretBytes;

use crate::atomic::{Inside, ModifyErrorKind, remove_checked_observed};
use crate::restore::rewrite_observed;
use crate::root::{FileStamp, ScanRoot};

/// What a file keeps once the entries the vault holds are taken out.
#[derive(Debug)]
pub enum Remains {
    /// Nothing: the vault holds every entry, and the file is removed.
    Nothing,
    /// These bytes: the file is rewritten to hold only the entries the
    /// vault does not ([`crate::without_entries`]).
    Bytes(SecretBytes),
    /// Everything: the vault holds none of its entries, and the file is
    /// left as it is.
    Everything,
}

/// What decides whether plaintext may be deleted.
pub trait DeleteGate {
    /// Why the gate refused.
    type Refusal;

    /// Conditions 1, 2 and 4: the files' secrets are committed and bound,
    /// every reference resolves, and the Recovery Kit is confirmed. It is
    /// asked twice; the second time it must also find the vault holding
    /// the same entries of each file as the first.
    ///
    /// # Errors
    /// The refusal, when any of them does not hold.
    fn verify(&mut self) -> Result<(), Self::Refusal>;

    /// What file `i` keeps, by the last answer of [`DeleteGate::verify`].
    fn remains(&self, i: usize) -> Remains;

    /// Condition 3: writes the encrypted backup of the files at the
    /// indices `which`, and returns its id once it is on disk.
    ///
    /// # Errors
    /// The refusal, when the backup could not be written.
    fn backup(&mut self, which: &[usize]) -> Result<String, Self::Refusal>;
}

/// The points [`delete_plaintext`] passes, in order. Tests stop it at each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeleteStep {
    Verified,
    BackedUp,
    Reverified,
    /// The file at this index was renamed aside, not yet unlinked.
    MovedAside(usize),
    /// The file at this index was removed.
    Removed(usize),
    /// The new contents of the file at this index are written beside it,
    /// not yet in its place.
    Staged(usize),
    /// The new contents of the file at this index have its name, and the
    /// old file is under a temporary name, not yet unlinked.
    Swapped(usize),
    /// The file at this index was rewritten.
    Rewritten(usize),
}

/// What [`delete_plaintext`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteOutcome {
    /// The encrypted backup's id; `None` when no file was to change.
    pub backup: Option<String>,
    pub removed: Vec<PathBuf>,
    pub rewritten: Vec<PathBuf>,
    /// Files the vault holds no entry of: left as they are.
    pub unchanged: Vec<PathBuf>,
    /// Files left in place, and why; and plaintext left under a temporary
    /// name after its file was changed, when it could not be unlinked
    /// ([`ModifyErrorKind::NotRemoved`], the temporary name given).
    pub kept: Vec<(PathBuf, ModifyErrorKind)>,
}

/// Removes or rewrites `files` (paths under `r` with the stamps they were
/// read with) once `gate` allows it. See the module documentation.
///
/// # Errors
/// The gate's refusal; then nothing was changed.
pub fn delete_plaintext<G: DeleteGate>(
    r: &ScanRoot,
    files: &[(PathBuf, FileStamp)],
    gate: &mut G,
    observe: &mut dyn FnMut(DeleteStep),
) -> Result<DeleteOutcome, G::Refusal> {
    gate.verify()?;
    observe(DeleteStep::Verified);
    let remains: Vec<Remains> = (0..files.len()).map(|i| gate.remains(i)).collect();
    let mut out = DeleteOutcome {
        backup: None,
        removed: Vec::new(),
        rewritten: Vec::new(),
        unchanged: Vec::new(),
        kept: Vec::new(),
    };
    let mut changing = Vec::new();
    for (i, left) in remains.iter().enumerate() {
        if matches!(left, Remains::Everything) {
            out.unchanged.push(files[i].0.clone());
        } else {
            changing.push(i);
        }
    }
    if changing.is_empty() {
        return Ok(out);
    }
    out.backup = Some(gate.backup(&changing)?);
    observe(DeleteStep::BackedUp);
    gate.verify()?;
    observe(DeleteStep::Reverified);
    for i in changing {
        let (rel, stamp) = &files[i];
        let now = SystemTime::now();
        let done = match &remains[i] {
            Remains::Nothing => remove_checked_observed(r, rel, stamp, now, &mut |_| {
                observe(DeleteStep::MovedAside(i));
            })
            .map(|()| (&mut out.removed, DeleteStep::Removed(i))),
            Remains::Bytes(b) => rewrite_observed(r, rel, b, stamp, now, &mut |at| match at {
                Inside::Staged => observe(DeleteStep::Staged(i)),
                Inside::Swapped => observe(DeleteStep::Swapped(i)),
                Inside::MovedAside | Inside::Checked => {}
            })
            .map(|_| (&mut out.rewritten, DeleteStep::Rewritten(i))),
            Remains::Everything => continue,
        };
        match done {
            Ok((list, step)) => {
                list.push(rel.clone());
                observe(step);
            }
            Err(e) => {
                // Rewritten, with the old file left: both are said.
                if e.kind == ModifyErrorKind::NotRemoved && matches!(remains[i], Remains::Bytes(_))
                {
                    out.rewritten.push(rel.clone());
                }
                out.kept.push((e.rel, e.kind));
            }
        }
    }
    Ok(out)
}
