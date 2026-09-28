//! What the daemon tells a client (SPEC §4.4: metadata only). These types
//! hold no [`crate::WireSecret`] and no free text from the vault: states,
//! counts, versions and fixed tokens.
//!
//! The two strings in [`StatusView`] come from the daemon, whose code
//! identity M1 clients cannot verify, so [`crate::Client::status`] passes
//! them through [`StatusView::sanitize`] before anyone prints them.

use envcloak_policy::{DenyReason, Mode, SubjectKind, Uses};
use serde::{Deserialize, Serialize};

use crate::proto::REASONS;

/// What [`StatusView::sanitize`] puts in place of a version that is not
/// one a daemon would send.
pub const UNRECOGNIZED_VERSION: &str = "unrecognized";
/// What [`StatusView::sanitize`] puts in place of a reason that is not one
/// of [`REASONS`].
pub const UNKNOWN_REASON: &str = "unknown";

/// `status`: the daemon, its vault, its lock, and its grants and proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    pub daemon: DaemonView,
    pub vault: VaultView,
    pub lock: LockView,
    pub approvals: ApprovalsView,
    pub audit: AuditStatusView,
}

impl StatusView {
    /// Replaces the daemon's strings with fixed text when they do not have
    /// the shape a daemon sends: [`DaemonView::version`] must be 1 to 32
    /// characters of `[0-9A-Za-z.+-]` (else [`UNRECOGNIZED_VERSION`]), and
    /// [`VaultView::unavailable`] one of [`REASONS`] (else
    /// [`UNKNOWN_REASON`]). A program running as the user can answer in
    /// the daemon's place (SPEC §1.1), and must not put terminal control
    /// sequences on the user's screen.
    pub fn sanitize(&mut self) {
        let v = &self.daemon.version;
        let version_ok = (1..=32).contains(&v.len())
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'));
        if !version_ok {
            self.daemon.version = UNRECOGNIZED_VERSION.to_owned();
        }
        if let Some(r) = self.vault.unavailable.as_mut() {
            if !REASONS.contains(&r.as_str()) {
                UNKNOWN_REASON.clone_into(r);
            }
        }
    }
}

/// The daemon process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonView {
    /// Its version, `CARGO_PKG_VERSION`. Checked by
    /// [`StatusView::sanitize`].
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
    /// [`VaultState::Unavailable`]: a fixed token, one of [`REASONS`].
    /// Checked by [`StatusView::sanitize`].
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

/// Grants, pending requests and the passphrase attempt limiter (SPEC
/// §10b "Passphrase attempts": `envcloak status` reports the failures).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalsView {
    /// Grants in force.
    pub grants: u32,
    /// Requests waiting for an approval.
    pub pending: u32,
    /// Failed proofs (wrong passphrases) since the last success.
    pub proof_failures: u32,
    /// Seconds before the next proof is admitted.
    pub proof_wait_secs: u64,
}

/// The audit log (SPEC §6.1 step 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditStatusView {
    /// The log is open for writing: the vault is unlocked and the log's
    /// directory usable. While unlocked and not open, requests that would
    /// release values are denied.
    pub open: bool,
    /// The last entry's sequence number, while open.
    pub head_seq: Option<u64>,
    /// Entries written since the head was last saved in the vault's header.
    pub unanchored: u64,
    /// Events held in memory until the log can be written.
    pub queued: u64,
    /// Events lost because that queue was full.
    pub dropped: u64,
}

/// `run.request`: the decision (SPEC §6.1 step 4, §10b).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum DecisionView {
    /// A grant covers the request. What a covered run must do follows.
    Covered {
        /// The grant's id, 26 Crockford base32 characters.
        grant: String,
        /// The effective policy: redact the command's output.
        redact: bool,
        /// The effective mode.
        mode: Mode,
        /// The manifest's hash differs from the one at approval; the
        /// bindings are still a subset, so nothing prompted.
        manifest_changed: bool,
    },
    /// No grant covers it; a person must approve request `request`.
    Pending {
        /// 8 Crockford base32 characters.
        request: String,
    },
    /// Denied without a prompt; `reason` is a `DenyReason` token.
    Denied { reason: String },
}

impl DecisionView {
    /// The denial reason, when the decision is a denial with a token this
    /// client knows.
    pub fn deny_reason(&self) -> Option<DenyReason> {
        match self {
            DecisionView::Denied { reason } => DenyReason::from_token(reason),
            _ => None,
        }
    }
}

/// `approve`: the grant created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedView {
    /// 26 Crockford base32 characters.
    pub grant: String,
    /// The grant's length, in seconds.
    pub expires_in_secs: u64,
}

/// `deny`: the request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeniedView {
    /// This was the third denial for the root within 10 minutes: the root
    /// is denied for 30 minutes.
    pub root_auto_denied: bool,
}

/// `grants.list`: the grants in force, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantsView {
    pub grants: Vec<GrantView>,
}

/// One grant (SPEC §10b). Every string is escaped before it is shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantView {
    /// 26 Crockford base32 characters.
    pub id: String,
    pub kind: SubjectKind,
    /// The agent's display name, when one is involved.
    pub label: Option<String>,
    pub root_pid: i32,
    pub root_exe: Option<String>,
    /// The project's canonical directory.
    pub project_dir: String,
    pub bindings: Vec<GrantBindingView>,
    pub mode: Mode,
    pub uses: Uses,
    /// When the grant was created, Unix seconds.
    pub created_secs: u64,
    /// Seconds left before it expires, by the nearer of its two clocks.
    pub remaining_secs: u64,
}

/// One binding of a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantBindingView {
    pub env_name: String,
    pub slug: String,
    pub live: bool,
}

/// `grants.revoke`: how many grants ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedView {
    pub revoked: u64,
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

/// `audit.verify`: the check of the audit log (SPEC §15.2 gate 33). Counts,
/// sequence numbers and fixed tokens only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditVerifyView {
    /// Segment files read.
    pub segments: u64,
    /// Entries read.
    pub entries: u64,
    /// The last sequence number the check reached.
    pub last_seq: u64,
    /// The first problem, at its sequence number; `None` when the log
    /// checks out.
    pub first_problem: Option<AuditProblemView>,
    /// Problems in all.
    pub problems: u64,
    /// The head saved in the vault's header.
    pub anchor: AnchorView,
    /// The entries after the anchor (all of them when there is none):
    /// entries removed from their end would not be noticed.
    pub unanchored_tail: Option<SeqRange>,
    /// The log ends in an entry cut short by a crash (never acknowledged).
    pub torn_tail: bool,
    /// Whether the log still ends where the daemon last wrote it. `None`
    /// when the daemon has not written to it since it was unlocked.
    pub live_head_matches: Option<bool>,
    /// Events held in memory until the log can be written (while the vault
    /// was locked, say), and events lost because that queue was full.
    pub queued: u64,
    pub dropped: u64,
}

/// A problem the check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditProblemView {
    pub seq: u64,
    pub kind: AuditProblemKind,
}

/// What kind of problem (`envcloak_core::audit::ProblemKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditProblemKind {
    /// The entry does not open: it was changed.
    Altered,
    /// The entry is not the one its predecessor chains to.
    ChainBroken,
    /// No entry has this number.
    Missing,
    /// The entry is out of place.
    Reordered,
    /// A segment's header does not authenticate, or its file cannot be
    /// read.
    SegmentDamaged,
    /// Bytes cannot be read as entries.
    Unreadable,
    /// The entry at the saved head is not the one the head names.
    AnchorMismatch,
}

/// What became of the saved head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorView {
    pub state: AnchorState,
    /// The saved head's sequence number.
    pub seq: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorState {
    /// No head saved yet.
    None,
    Matched,
    Mismatch,
    /// The saved head's entry is not in the log.
    Missing,
}

/// Sequence numbers from `first` to `last`, both included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeqRange {
    pub first: u64,
    pub last: u64,
}

impl From<&envcloak_core::audit::VerifyReport> for AuditVerifyView {
    fn from(r: &envcloak_core::audit::VerifyReport) -> Self {
        use envcloak_core::audit::{AnchorCheck, ProblemKind};
        let kind = |k: ProblemKind| match k {
            ProblemKind::Altered => AuditProblemKind::Altered,
            ProblemKind::ChainBroken => AuditProblemKind::ChainBroken,
            ProblemKind::Missing => AuditProblemKind::Missing,
            ProblemKind::Reordered => AuditProblemKind::Reordered,
            ProblemKind::SegmentDamaged => AuditProblemKind::SegmentDamaged,
            ProblemKind::Unreadable => AuditProblemKind::Unreadable,
            ProblemKind::AnchorMismatch => AuditProblemKind::AnchorMismatch,
        };
        let anchor = match r.anchor {
            AnchorCheck::None => AnchorView {
                state: AnchorState::None,
                seq: None,
            },
            AnchorCheck::Matched { seq } => AnchorView {
                state: AnchorState::Matched,
                seq: Some(seq),
            },
            AnchorCheck::Mismatch { seq } => AnchorView {
                state: AnchorState::Mismatch,
                seq: Some(seq),
            },
            AnchorCheck::Missing { seq } => AnchorView {
                state: AnchorState::Missing,
                seq: Some(seq),
            },
        };
        AuditVerifyView {
            segments: u64::try_from(r.segments).unwrap_or(u64::MAX),
            entries: r.entries,
            last_seq: r.last_seq,
            first_problem: r.first_problem.map(|p| AuditProblemView {
                seq: p.seq,
                kind: kind(p.kind),
            }),
            problems: r.problems,
            anchor,
            unanchored_tail: r
                .unanchored_tail
                .map(|(first, last)| SeqRange { first, last }),
            torn_tail: r.torn_tail,
            live_head_matches: None,
            queued: 0,
            dropped: 0,
        }
    }
}
