//! File ownership and creation modes (SPEC §5 "Vault": every directory is
//! 0700 and every file 0600; §4.2: the daemon binds under umask 077).
//!
//! - [`restrict_umask`]: sets the process umask to 077, so every file and
//!   directory the process creates, including the SQLite WAL, shared-memory
//!   and journal files it never opens itself, starts private.
//! - [`effective_uid`]: the uid that owns what this process creates, for
//!   checking that a directory it trusts is its own.

/// The umask [`restrict_umask`] sets: no permissions for group or others.
pub const PRIVATE_UMASK: u32 = 0o077;

/// Sets the process umask to [`PRIVATE_UMASK`] and returns the previous
/// mask. The umask is process-wide: call it at startup, before any thread
/// creates files.
pub fn restrict_umask() -> u32 {
    // SAFETY: umask has no preconditions and cannot fail.
    let previous = unsafe { libc::umask(PRIVATE_UMASK as libc::mode_t) };
    u32::from(previous)
}

/// The effective uid of this process.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}
