//! The `<data>/policy-epoch` anti-rollback sidecar for standing approvals
//! (SPEC §10b; M2 plan D-10, task M2-15).
//!
//! Each vault mutation that creates, updates, or deletes a standing approval
//! increments the vault header's `standing_set.generation` and recomputes
//! `standing_set.set_digest` over all active standing records in one vault
//! transaction, bumps the in-memory `policy_epoch`, and then atomically
//! writes `<data>/policy-epoch` (`0600`, `O_NOFOLLOW`, verified `fstat`,
//! write-sync-rename-dir-fsync).
//!
//! At unlock, [`PolicyEpoch::reconcile`] compares the vault header's
//! [`StandingSetHeader`] against `<data>/policy-epoch`:
//! - Equal `(generation, set_digest)` -> [`EpochState::Verified`].
//! - `vault.generation > sidecar.generation` -> crash between the vault
//!   commit and the sidecar commit; rewrites `<data>/policy-epoch` from the
//!   vault header -> [`EpochState::Verified`].
//! - `vault.generation < sidecar.generation`, digest mismatch at equal
//!   generation, missing sidecar when `vault.generation > 0`, or corrupt
//!   sidecar -> [`EpochState::Unverified`]; standing approvals are suspended
//!   (`policy_epoch_unverified`) until confirmed by passphrase proof.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use envcloak_core::vault::StandingSetHeader;

const MAGIC: &[u8; 6] = b"ECPE\x00\x01";
const SIDECAR_LEN: usize = 6 + 16 + 8 + 32;
const SIDECAR_NAME: &str = "policy-epoch";
const SIDECAR_TMP_NAME: &str = "policy-epoch.tmp";

/// Contents of `<data>/policy-epoch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sidecar {
    pub vault_id: [u8; 16],
    pub generation: u64,
    pub set_digest: [u8; 32],
}

/// Result of reading `<data>/policy-epoch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidecarState {
    Present(Sidecar),
    Missing,
    Corrupt,
}

/// Whether the vault's standing-approval set has been verified against
/// `<data>/policy-epoch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochState {
    Verified,
    Unverified,
}

/// Reader and atomic writer for `<data>/policy-epoch`.
#[derive(Debug, Clone)]
pub struct PolicyEpoch {
    vault_id: [u8; 16],
    path: PathBuf,
}

impl PolicyEpoch {
    /// Creates a [`PolicyEpoch`] handle for `vault_id` in `data_dir`.
    pub fn new(vault_id: [u8; 16], data_dir: &Path) -> Self {
        PolicyEpoch {
            vault_id,
            path: data_dir.join(SIDECAR_NAME),
        }
    }

    /// Path to `<data>/policy-epoch`.
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads and validates `<data>/policy-epoch`.
    pub fn load(&self) -> SidecarState {
        let mut f = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return SidecarState::Missing,
            Err(_) => return SidecarState::Corrupt,
        };
        let Ok(m) = f.metadata() else {
            return SidecarState::Corrupt;
        };
        if !m.is_file()
            || m.uid() != envcloak_sys::effective_uid()
            || m.mode() & 0o077 != 0
            || m.len() != SIDECAR_LEN as u64
        {
            return SidecarState::Corrupt;
        }
        let mut buf = [0u8; SIDECAR_LEN + 1];
        let Ok(n) = f.read(&mut buf) else {
            return SidecarState::Corrupt;
        };
        if n != SIDECAR_LEN || &buf[..6] != MAGIC {
            return SidecarState::Corrupt;
        }
        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&buf[6..22]);
        let mut gen_bytes = [0u8; 8];
        gen_bytes.copy_from_slice(&buf[22..30]);
        let generation = u64::from_be_bytes(gen_bytes);
        let mut set_digest = [0u8; 32];
        set_digest.copy_from_slice(&buf[30..62]);
        SidecarState::Present(Sidecar {
            vault_id,
            generation,
            set_digest,
        })
    }

    /// Reconciles `vault_header` with `sidecar` at unlock.
    pub fn reconcile(&self, vault_header: StandingSetHeader, sidecar: SidecarState) -> EpochState {
        let generation = vault_header.generation;
        let set_digest = vault_header.set_digest;
        match sidecar {
            SidecarState::Present(s) if s.vault_id == self.vault_id => {
                if generation == s.generation && set_digest == s.set_digest {
                    EpochState::Verified
                } else if generation > s.generation {
                    match self.commit(vault_header) {
                        Ok(()) => EpochState::Verified,
                        Err(_) => EpochState::Unverified,
                    }
                } else {
                    EpochState::Unverified
                }
            }
            SidecarState::Missing if generation == 0 => match self.commit(vault_header) {
                Ok(()) => EpochState::Verified,
                Err(_) => EpochState::Unverified,
            },
            SidecarState::Present(_) | SidecarState::Missing | SidecarState::Corrupt => {
                EpochState::Unverified
            }
        }
    }

    /// Verifies that the on-disk sidecar still matches `vault_header` while
    /// the vault is unlocked.
    pub fn verify_live(&self, vault_header: StandingSetHeader) -> EpochState {
        let generation = vault_header.generation;
        let set_digest = vault_header.set_digest;
        match self.load() {
            SidecarState::Present(s)
                if s.vault_id == self.vault_id
                    && generation == s.generation
                    && set_digest == s.set_digest =>
            {
                EpochState::Verified
            }
            _ => EpochState::Unverified,
        }
    }

    /// Atomically writes, syncs, renames, and directory-syncs `<data>/policy-epoch`.
    pub fn commit(&self, header: StandingSetHeader) -> Result<(), io::Error> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let dm = std::fs::symlink_metadata(dir)?;
        if !dm.is_dir() || dm.uid() != envcloak_sys::effective_uid() || dm.mode() & 0o077 != 0 {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        let tmp = dir.join(SIDECAR_TMP_NAME);
        let _ = std::fs::remove_file(&tmp);

        let mut buf = [0u8; SIDECAR_LEN];
        buf[..6].copy_from_slice(MAGIC);
        buf[6..22].copy_from_slice(&self.vault_id);
        buf[22..30].copy_from_slice(&header.generation.to_be_bytes());
        buf[30..62].copy_from_slice(&header.set_digest);

        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tmp)?;
            let m = f.metadata()?;
            if !m.is_file() || m.uid() != envcloak_sys::effective_uid() || m.mode() & 0o077 != 0 {
                let _ = std::fs::remove_file(&tmp);
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            f.write_all(&buf)?;
            envcloak_sys::sync_file(&f)?;
        }
        envcloak_sys::pause_point("standing.after_sidecar_write");
        envcloak_sys::panic_point("standing.after_sidecar_write");

        std::fs::rename(&tmp, &self.path)?;
        envcloak_sys::pause_point("standing.after_sidecar_rename");
        envcloak_sys::panic_point("standing.after_sidecar_rename");

        let dir_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(dir)?;
        envcloak_sys::sync_file(&dir_file)?;
        envcloak_sys::pause_point("standing.after_sidecar_sync");
        envcloak_sys::panic_point("standing.after_sidecar_sync");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn sidecar_roundtrip_and_reconcile() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let vault_id = [0x42u8; 16];
        let pe = PolicyEpoch::new(vault_id, tmp.path());

        assert_eq!(pe.load(), SidecarState::Missing);
        let h0 = StandingSetHeader {
            generation: 0,
            set_digest: [0u8; 32],
        };
        assert_eq!(pe.reconcile(h0, pe.load()), EpochState::Verified);
        assert_eq!(
            pe.load(),
            SidecarState::Present(Sidecar {
                vault_id,
                generation: 0,
                set_digest: [0u8; 32],
            })
        );

        // Vault generation ahead of sidecar (crash between step 1 and step 3) heals.
        let h1 = StandingSetHeader {
            generation: 1,
            set_digest: [0x11u8; 32],
        };
        assert_eq!(pe.reconcile(h1, pe.load()), EpochState::Verified);
        assert_eq!(
            pe.load(),
            SidecarState::Present(Sidecar {
                vault_id,
                generation: 1,
                set_digest: [0x11u8; 32],
            })
        );

        // Rollback of vault generation (< sidecar.generation) is Unverified.
        assert_eq!(pe.reconcile(h0, pe.load()), EpochState::Unverified);

        // Digest mismatch at equal generation is Unverified.
        let h1_bad = StandingSetHeader {
            generation: 1,
            set_digest: [0x22u8; 32],
        };
        assert_eq!(pe.reconcile(h1_bad, pe.load()), EpochState::Unverified);

        // Missing sidecar when generation > 0 is Unverified.
        std::fs::remove_file(pe.path()).unwrap();
        assert_eq!(pe.reconcile(h1, pe.load()), EpochState::Unverified);

        // Corrupt sidecar is Unverified.
        std::fs::write(pe.path(), b"corrupt").unwrap();
        std::fs::set_permissions(pe.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(pe.load(), SidecarState::Corrupt);
        assert_eq!(pe.reconcile(h0, pe.load()), EpochState::Unverified);
    }
}
