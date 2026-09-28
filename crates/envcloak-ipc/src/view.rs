//! What the daemon tells a client (SPEC §4.4: metadata only). These types
//! hold no [`crate::WireSecret`] and no free text from the vault: states,
//! counts, versions and fixed tokens.

use serde::{Deserialize, Serialize};

/// `status`: the daemon, its vault and its lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    pub daemon: DaemonView,
    pub vault: VaultView,
    pub lock: LockView,
}

/// The daemon process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonView {
    /// Its version, `CARGO_PKG_VERSION`.
    pub version: String,
    pub pid: u32,
    pub hardening: HardeningView,
    /// Linux: `XDG_RUNTIME_DIR` was unset, so the socket is under
    /// `XDG_STATE_HOME`.
    pub runtime_dir_fallback: bool,
}

/// What protects a process, read back from the kernel
/// (`envcloak_sys::Hardening`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningView {
    /// `RLIMIT_CORE` is 0.
    pub core_dumps_off: bool,
    /// Linux: `PR_GET_DUMPABLE` is 0.
    pub non_dumpable: bool,
    /// macOS: signed with the hardened runtime and without
    /// `get-task-allow`. `None` elsewhere.
    pub hardened_runtime: Option<bool>,
}

impl HardeningView {
    /// Whether every protection this platform has took effect: core dumps
    /// off, and the hardened runtime on macOS or non-dumpable on Linux.
    /// Builds without them report "unhardened" (SPEC §5 "Process
    /// hardening").
    pub fn hardened(&self) -> bool {
        self.core_dumps_off
            && match self.hardened_runtime {
                Some(runtime) => runtime,
                None => self.non_dumpable,
            }
    }
}

impl From<envcloak_sys::Hardening> for HardeningView {
    fn from(h: envcloak_sys::Hardening) -> Self {
        HardeningView {
            core_dumps_off: h.core_dumps_off,
            non_dumpable: h.non_dumpable,
            hardened_runtime: h.hardened_runtime,
        }
    }
}

/// The vault as the daemon holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultView {
    pub state: VaultState,
    /// Set while unlocked.
    pub integrity: Option<Integrity>,
    /// Unlocked, but open read-only: it failed its integrity check or
    /// could not be migrated.
    pub read_only: bool,
    /// Why the vault could not be opened, when `state` is
    /// [`VaultState::Unavailable`]: a fixed token.
    pub unavailable: Option<String>,
    /// An unlock or `vault create` is running.
    pub busy: bool,
    /// Wrong passphrases since the daemon started.
    pub failed_unlocks: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultState {
    /// No vault yet: run `envcloak vault create`.
    Absent,
    Locked,
    Unlocked,
    /// The vault file exists but could not be opened.
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Integrity {
    Ok,
    /// The vault was changed outside EnvCloak; it is open read-only.
    Tampered,
}

/// The lock timer and what last locked the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockView {
    pub last_reason: Option<LockReason>,
    /// The idle limit, in seconds.
    pub idle_limit_secs: u64,
    /// Seconds of awake time left before the idle lock, while unlocked.
    pub idle_remaining_secs: Option<u64>,
}

/// What locked the vault (SPEC §5 "Lock").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockReason {
    /// A client asked (`envcloak lock`).
    Request,
    /// No request for the idle limit.
    Idle,
    /// The machine slept.
    Sleep,
    /// The daemon was asked to stop.
    Signal,
}

impl LockReason {
    /// The reason as a word, for status output.
    pub fn as_str(self) -> &'static str {
        match self {
            LockReason::Request => "request",
            LockReason::Idle => "idle",
            LockReason::Sleep => "sleep",
            LockReason::Signal => "signal",
        }
    }
}

/// `vault.create`: the vault exists, under the passphrase and the Recovery
/// Kit the client sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedView {
    /// A lock (a request, sleep or a signal) arrived while Argon2id ran: the
    /// vault was created and then locked. The kit is valid all the same.
    pub locked: bool,
    pub integrity: Integrity,
    pub read_only: bool,
}

/// `unlock`: the vault is unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockedView {
    pub integrity: Integrity,
    pub read_only: bool,
    /// It was unlocked already; nothing was checked.
    pub already: bool,
}

/// `lock`: the vault is locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedView {
    /// It was unlocked until this request.
    pub was_unlocked: bool,
}
