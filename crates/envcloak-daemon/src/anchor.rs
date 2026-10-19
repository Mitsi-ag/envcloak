//! Keychain rollback anchor storage (`D3-12`, SPEC §5 "Integrity", M3-16).
//!
//! Stores a 68-byte [`Anchor`] `(vault_id, epoch, write_counter, state_digest,
//! audit_seq)` per vault in the macOS data protection keychain (`ai.envcloak.anchor`
//! under `<TEAMID>.ai.envcloak`), with an in-memory store for deterministic
//! unit and integration tests.

use std::collections::BTreeMap;
use std::sync::Mutex;

use envcloak_core::crypto::VaultId;
use envcloak_core::vault::Anchor;
use envcloak_sys::{
    KeychainAnchorError, is_keychain_anchor_available, read_keychain_anchor, write_keychain_anchor,
};

use crate::app::hex_encode;

/// Why a keychain rollback anchor operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorError {
    /// Keychain rollback anchor is unavailable on this platform or build
    /// (Linux, or a build without the helper's provisioning profile).
    Unavailable,
    /// The stored anchor record did not have the 68-byte format or named
    /// another vault.
    Corrupt,
    /// The keychain operation failed.
    Storage,
}

impl core::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            AnchorError::Unavailable => "unavailable",
            AnchorError::Corrupt => "corrupt",
            AnchorError::Storage => "storage",
        })
    }
}

impl From<KeychainAnchorError> for AnchorError {
    fn from(e: KeychainAnchorError) -> Self {
        match e {
            KeychainAnchorError::Unavailable => AnchorError::Unavailable,
            KeychainAnchorError::InvalidRecord => AnchorError::Corrupt,
            KeychainAnchorError::Storage => AnchorError::Storage,
        }
    }
}

/// Storage backend for the vault rollback anchor (M3-16).
pub trait AnchorStore: Send + Sync + core::fmt::Debug {
    /// Whether this store is available on this build and platform.
    fn is_available(&self) -> bool {
        true
    }

    /// Reads the stored anchor for `vault`, or `Ok(None)` when none exists.
    fn read(&self, vault: VaultId) -> Result<Option<Anchor>, AnchorError>;

    /// Writes or updates the anchor for `a.vault_id`.
    fn write(&self, a: &Anchor) -> Result<(), AnchorError>;
}

/// The production macOS data-protection keychain anchor store (`D3-12`).
#[derive(Debug, Default, Clone, Copy)]
pub struct KeychainAnchorStore;

impl AnchorStore for KeychainAnchorStore {
    fn is_available(&self) -> bool {
        is_keychain_anchor_available()
    }

    fn read(&self, vault: VaultId) -> Result<Option<Anchor>, AnchorError> {
        let account = hex_encode(&vault.0);
        let Some(raw) = read_keychain_anchor(&account)? else {
            return Ok(None);
        };
        let anchor = Anchor::decode(&raw).map_err(|_| AnchorError::Corrupt)?;
        Ok(Some(anchor))
    }

    fn write(&self, a: &Anchor) -> Result<(), AnchorError> {
        let account = hex_encode(&a.vault_id.0);
        let bytes = a.encode();
        write_keychain_anchor(&account, &bytes)?;
        Ok(())
    }
}

/// In-memory anchor store for tests (`M3-16`).
#[derive(Debug, Default)]
pub struct MemoryAnchorStore {
    available: bool,
    inner: Mutex<BTreeMap<[u8; 16], Anchor>>,
}

#[allow(dead_code)]
impl MemoryAnchorStore {
    pub fn new() -> Self {
        Self {
            available: true,
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn unavailable() -> Self {
        Self {
            available: false,
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    /// Removes the stored anchor for `vault` (simulating a missing keychain
    /// item on a vault that previously had one).
    pub fn remove(&self, vault: VaultId) -> Option<Anchor> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&vault.0)
    }

    /// Returns all stored anchors.
    pub fn snapshot(&self) -> BTreeMap<[u8; 16], Anchor> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl AnchorStore for MemoryAnchorStore {
    fn is_available(&self) -> bool {
        self.available
    }

    fn read(&self, vault: VaultId) -> Result<Option<Anchor>, AnchorError> {
        if !self.available {
            return Err(AnchorError::Unavailable);
        }
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&vault.0)
            .copied())
    }

    fn write(&self, a: &Anchor) -> Result<(), AnchorError> {
        if !self.available {
            return Err(AnchorError::Unavailable);
        }
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(a.vault_id.0, *a);
        Ok(())
    }
}
