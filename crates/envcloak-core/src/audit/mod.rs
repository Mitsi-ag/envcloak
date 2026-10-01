//! The audit log (SPEC §3 principle 4, §6.1 step 5, §15.2 gate 33):
//! append-only, sealed, and chained, so a change to it is evident (it is
//! tamper-evident, not tamper-proof: a program running as the user can
//! still delete it).
//!
//! - [`AuditRecord`]: one entry's contents, metadata only; the daemon
//!   masks the command line before building it ([`record`] caps the rest).
//! - [`AuditWriter`]: appends entries to segment files under
//!   `<data>/audit/`, each sealed under the `audit` subkey and chained with
//!   a keyed MAC; an entry is flushed (`F_FULLFSYNC` on macOS), and the
//!   directories that name its segment after it, before
//!   [`AuditWriter::append`] returns, and a failed append leaves the log
//!   as it was, so the daemon can deny the request it was for. The file
//!   format is in `segment.rs` and docs/VAULT.md "Audit log".
//! - [`verify`] and [`read_entries`]: check the whole log and report the
//!   first problem at its sequence number, whether the head saved in the
//!   vault's header (the anchor) is in it, and the unanchored tail.
//! - [`crate::vault::Vault::open_audit`], [`crate::vault::Vault::verify_audit`]
//!   and [`crate::vault::Vault::read_audit`] do the same with the unlocked
//!   vault's keys and saved head.
//!
//! Errors are [`AuditError`]s with fixed messages and no values.

mod record;
mod segment;
mod verify;

pub use record::{
    AuditKind, AuditRecord, DecisionSummary, MAX_ARGS, MAX_ARGV_BYTES, MAX_ENTRY, MAX_ITEMS,
    MAX_TEXT, ProjectSummary, SubjectSummary,
};
pub use segment::{AuditIo, AuditWriter, HEADER_LEN, MAX_SEGMENT, OpenReport, OsIo};
pub use verify::{
    AnchorCheck, AuditEntry, Problem, ProblemKind, VerifyReport, read_entries, verify,
};

use crate::vault::{AuditHead, PathError, Vault, VaultError};

/// Test support only: the torn-tail check's work budget and the work done
/// (review R-17).
#[cfg(feature = "testing")]
pub mod testing {
    /// The most work the torn-tail check of one [`super::verify`], or one
    /// [`super::AuditWriter::open`], does (see `TAIL_CHECK_BUDGET` in
    /// `verify.rs`).
    pub const TAIL_CHECK_BUDGET: usize = super::verify::TAIL_CHECK_BUDGET;

    /// How many lengths the scans of every length have tried on this
    /// thread so far, each one chain value or tag computed in full.
    pub fn lengths_tried() -> usize {
        crate::crypto::lengths_tried()
    }
}

/// An audit log failure. Carries its kind only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditError {
    kind: AuditErrorKind,
}

/// What went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuditErrorKind {
    /// The log's directory, or a segment, is not this user's private
    /// directory or file (a symlink, another owner, writable by others).
    Unsafe,
    /// A filesystem operation failed.
    Io(std::io::ErrorKind),
    /// Flushing an entry to disk failed: it may not be durable, so it was
    /// not acknowledged.
    Sync,
    /// Sealing an entry failed.
    Crypto,
    /// An entry exceeds [`MAX_ENTRY`] after its strings were capped.
    TooLarge,
    /// A segment cannot be read as one.
    Unreadable,
    /// The sequence numbers are used up.
    Full,
}

impl AuditErrorKind {
    /// The fixed message for this kind.
    pub const fn message(self) -> &'static str {
        match self {
            AuditErrorKind::Unsafe => {
                "the audit log's directory or a segment has unsafe permissions or ownership"
            }
            AuditErrorKind::Io(_) => "the audit log could not be read or written",
            AuditErrorKind::Sync => "the audit entry could not be flushed to disk",
            AuditErrorKind::Crypto => "the audit entry could not be sealed",
            AuditErrorKind::TooLarge => "the audit entry is too large",
            AuditErrorKind::Unreadable => "an audit log segment cannot be read",
            AuditErrorKind::Full => "the audit log's sequence numbers are used up",
        }
    }

    /// The stable token.
    pub const fn token(self) -> &'static str {
        match self {
            AuditErrorKind::Unsafe => "unsafe",
            AuditErrorKind::Io(_) => "io",
            AuditErrorKind::Sync => "sync",
            AuditErrorKind::Crypto => "crypto",
            AuditErrorKind::TooLarge => "too_large",
            AuditErrorKind::Unreadable => "unreadable",
            AuditErrorKind::Full => "full",
        }
    }
}

impl AuditError {
    pub fn kind(&self) -> AuditErrorKind {
        self.kind
    }
}

impl From<AuditErrorKind> for AuditError {
    fn from(kind: AuditErrorKind) -> Self {
        AuditError { kind }
    }
}

impl From<std::io::Error> for AuditError {
    fn from(e: std::io::Error) -> Self {
        AuditErrorKind::Io(e.kind()).into()
    }
}

impl From<PathError> for AuditError {
    fn from(_: PathError) -> Self {
        AuditErrorKind::Unsafe.into()
    }
}

impl core::fmt::Display for AuditError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.kind.message())
    }
}

impl std::error::Error for AuditError {}

/// The unlocked vault's audit log.
impl Vault {
    /// The head saved in the header: `None` before the first save, and
    /// when the vault failed its integrity check (its header cannot be
    /// trusted).
    pub fn audit_anchor(&self) -> Option<AuditHead> {
        self.header().ok().and_then(|h| h.audit_head)
    }

    /// Opens the writer of this vault's log, after the head its header
    /// saved.
    ///
    /// # Errors
    /// As [`AuditWriter::open`].
    pub fn open_audit(&self) -> Result<(AuditWriter, OpenReport), AuditError> {
        AuditWriter::open(&self.paths().audit_dir, self.keys(), self.audit_anchor())
    }

    /// Test support only: [`Vault::open_audit`] with another [`AuditIo`].
    #[cfg(feature = "testing")]
    pub fn open_audit_with_io(
        &self,
        io: Box<dyn AuditIo>,
        max_segment: u64,
    ) -> Result<(AuditWriter, OpenReport), AuditError> {
        AuditWriter::open_with_io(
            &self.paths().audit_dir,
            self.keys(),
            self.audit_anchor(),
            io,
            max_segment,
        )
    }

    /// Checks this vault's log against the head its header saved.
    ///
    /// # Errors
    /// As [`verify`].
    pub fn verify_audit(&self) -> Result<VerifyReport, AuditError> {
        verify(&self.paths().audit_dir, self.keys(), self.audit_anchor())
    }

    /// The entries of this vault's log that open, and the check's report.
    ///
    /// # Errors
    /// As [`verify`].
    pub fn read_audit(&self) -> Result<(Vec<AuditEntry>, VerifyReport), AuditError> {
        read_entries(&self.paths().audit_dir, self.keys(), self.audit_anchor())
    }

    /// Saves `head` in the sealed header, in a write transaction of its
    /// own.
    ///
    /// # Errors
    /// As [`Vault::transact`]: a vault that failed its integrity check is
    /// read-only.
    pub fn save_audit_head(&mut self, head: AuditHead) -> Result<(), VaultError> {
        self.transact(|t| {
            t.set_audit_head(head);
            Ok(())
        })
    }
}
