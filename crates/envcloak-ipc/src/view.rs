//! What the daemon tells a client (SPEC §4.4: metadata only), and what
//! the CLI prints: every command's output is one of these types, rendered
//! as text or JSON (`envcloak`'s `Render`).
//!
//! No type here can hold a value. Each implements [`View`], which needs
//! `Clone`, and [`crate::WireSecret`], the only way a value crosses the
//! socket, has no `Clone`: a view with a value in it does not compile.
//! Beyond that, the strings here are metadata: states, counts, versions,
//! fixed tokens, and names and paths (slugs, variables, an account), which
//! the CLI escapes before it prints them.
//!
//! The two strings in [`StatusView`] come from the daemon, whose code
//! identity M1 clients cannot verify, so [`crate::Client::status`] passes
//! them through [`StatusView::sanitize`] before anyone prints them.

use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{Classification, ItemMeta};
use envcloak_policy::{DenyReason, Mode, PendingId, PendingState, SubjectKind, Uses};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::proto::REASONS;

/// What a client may print: a type of this module. `Clone` is the point:
/// [`crate::WireSecret`] has none, so a type holding a value cannot be a
/// view.
pub trait View: Clone + core::fmt::Debug + Serialize + DeserializeOwned {}

macro_rules! views {
    ($($t:ty),* $(,)?) => {
        $(impl View for $t {})*
    };
}

views!(
    StatusView,
    DecisionView,
    ApprovedView,
    DeniedView,
    GrantsView,
    RevokedView,
    CreatedView,
    UnlockedView,
    LockedView,
    AuditVerifyView,
    ItemsView,
    ItemView,
    AddedView,
    TargetView,
    RotatedView,
    RemovedView,
    CheckView,
    CheckReport,
    RefEditView,
    ImportPlanView,
    VerifyView,
    FileBackupView,
    RecoveryConfirmedView,
    BackupView,
    RecoveredView,
    ImportReport,
    DeleteReport,
    UndoReport,
    InitReport,
    PendingStateView,
    PendingListView,
);

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
    /// `vault.recover` closed the vault to put a backup's in its place.
    Restore,
}

impl LockReason {
    /// The reason as a word, for status output.
    pub fn as_str(self) -> &'static str {
        match self {
            LockReason::Request => "request",
            LockReason::Idle => "idle",
            LockReason::Sleep => "sleep",
            LockReason::Signal => "signal",
            LockReason::Restore => "restore",
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
    /// Entries in the log after the head saved in the vault's header.
    pub unanchored: u64,
    /// The last try to save the head in the vault's header failed; the
    /// daemon tries again, at most every 15 minutes.
    pub anchor_failed: bool,
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

/// `pending.state`: how a request stands (SPEC §6.1 step 4), told only to
/// the request's own process tree; anyone else is told
/// [`PendingState::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingStateView {
    pub state: PendingState,
}

/// The bindings `pending.list` names for one request; the rest are
/// counted ([`PendingView::more_bindings`]). With at most 20 requests
/// pending (SPEC §10a), each project path at most 4096 bytes and each
/// agent name at most 64, the whole listing then fits in one frame
/// however many bindings a request has (a request's env file may name
/// thousands): `envcloak approve` shows every binding in its statement.
pub const MAX_LISTED_BINDINGS: usize = 32;

/// `pending.list`: the requests waiting for approval that the caller may
/// approve, oldest first; an empty list to a caller that may approve none
/// (SPEC §6.1 step 4, §10b).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingListView {
    pub requests: Vec<PendingView>,
}

impl PendingListView {
    /// Whether every request has the shape a daemon sends: a request id in
    /// its canonical form, once, and slugs for bindings, at most
    /// [`MAX_LISTED_BINDINGS`] of them, with no more counted unless that
    /// many are named. A program answering in the daemon's place could
    /// send anything (SPEC §1.1); the strings are still escaped before
    /// they are printed.
    pub fn well_formed(&self) -> bool {
        let mut seen: Vec<PendingId> = Vec::with_capacity(self.requests.len());
        for r in &self.requests {
            let Some(id) = PendingId::parse(&r.request) else {
                return false;
            };
            if id.to_string() != r.request
                || seen.contains(&id)
                || r.bindings.len() > MAX_LISTED_BINDINGS
                || (r.more_bindings > 0 && r.bindings.len() < MAX_LISTED_BINDINGS)
                || r.bindings
                    .iter()
                    .any(|b| envcloak_core::vault::Slug::new(b).is_err())
            {
                return false;
            }
            seen.push(id);
        }
        true
    }
}

/// One request waiting for approval, as `envcloak pending` shows it.
/// Metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingView {
    /// 8 Crockford base32 characters.
    pub request: String,
    /// How long it has waited, in seconds of awake time.
    pub age_secs: u64,
    /// How long it may still wait before it expires.
    pub expires_in_secs: u64,
    /// The requester's kind.
    pub kind: SubjectKind,
    /// The agent's display name, when one is involved.
    pub agent: Option<String>,
    /// The project's canonical directory.
    pub project: String,
    /// The slugs of the items its first [`MAX_LISTED_BINDINGS`] bindings
    /// name, in the request's order.
    pub bindings: Vec<String>,
    /// How many of its bindings are not in `bindings`.
    pub more_bindings: u64,
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
    /// The log ends in what a crash in the middle of an append leaves:
    /// part of one entry, or of a new segment's header, with no whole entry
    /// in it and not covered by the saved head. Anything else is a problem.
    pub torn_tail: bool,
    /// How many bytes that is.
    pub torn_bytes: u64,
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
            torn_bytes: r.torn_bytes,
            live_head_matches: None,
            queued: 0,
            dropped: 0,
        }
    }
}

/// `items.list`: every item, sorted by slug.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemsView {
    pub items: Vec<ItemView>,
}

/// An item's metadata (SPEC §5 "Items"), never its value. How much of it
/// is filled depends on who asked: `ls` gets the summary, `ls --long` the
/// account too, and `show` everything ([`ItemDetail`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemView {
    /// 26 Crockford base32 characters.
    pub id: String,
    pub slug: String,
    pub class: ItemClassView,
    pub title: String,
    /// A provider registry id.
    pub provider: Option<String>,
    pub classification: ClassificationView,
    pub env_hint: Option<String>,
    pub allow_short: bool,
    /// Sorted by name.
    pub fields: Vec<FieldView>,
    /// Unix seconds.
    pub created_secs: u64,
    pub updated_secs: u64,
    pub rotated_secs: Option<u64>,
    pub expires_secs: Option<u64>,
    /// Who owns or pays for the key: personal, so filled only for
    /// `ls --long` and `show`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountView>,
    /// The rest, for `show`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<ItemDetailView>,
}

/// How much of an item [`ItemView::from_meta`] fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemDetail {
    /// `ls`: no account, no detail.
    Summary,
    /// `ls --long`: the account too.
    Long,
    /// `show`: everything.
    Full,
}

impl ItemView {
    /// The view of `m` at `detail`.
    pub fn from_meta(m: &ItemMeta, detail: ItemDetail) -> Self {
        let d = &m.details;
        let account = matches!(detail, ItemDetail::Long | ItemDetail::Full).then(|| AccountView {
            email: d.account.email.clone(),
            label: d.account.label.clone(),
            org_id: d.account.org_id.clone(),
        });
        let full = (detail == ItemDetail::Full).then(|| ItemDetailView {
            allowed_hosts: d.allowed_hosts.clone(),
            tags: d.tags.clone(),
            links: LinksView {
                docs: d.links.docs.clone(),
                billing: d.links.billing.clone(),
                keys_page: d.links.keys_page.clone(),
                dashboard: d.links.dashboard.clone(),
            },
            last_used_secs: d.last_used_at,
            notes: (!d.notes.is_empty()).then(|| d.notes.clone()),
        });
        ItemView {
            id: m.id.to_string(),
            slug: m.slug.as_str().to_owned(),
            class: ItemClassView::from(m.class),
            title: d.title.clone(),
            provider: d.provider.clone(),
            classification: ClassificationView::from(d.classification),
            env_hint: d.env_hint.clone(),
            allow_short: d.allow_short,
            fields: m
                .fields
                .iter()
                .map(|f| FieldView {
                    name: f.name.as_str().to_owned(),
                    prior_count: f.prior_count,
                    created_secs: f.created_at,
                    updated_secs: f.updated_at,
                })
                .collect(),
            created_secs: m.created_at,
            updated_secs: m.updated_at,
            rotated_secs: d.rotated_at,
            expires_secs: d.expires_at,
            account,
            detail: full,
        }
    }
}

/// An item's class (SPEC §2a-bis): only secrets are bound to variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemClassView {
    Secret,
    Card,
    IssuerCredential,
    /// A class this build does not know.
    Other,
}

impl From<ItemClass> for ItemClassView {
    fn from(c: ItemClass) -> Self {
        match c {
            ItemClass::Secret => ItemClassView::Secret,
            ItemClass::Card => ItemClassView::Card,
            ItemClass::IssuerCredential => ItemClassView::IssuerCredential,
            ItemClass::None => ItemClassView::Other,
        }
    }
}

/// Test, live or unknown (SPEC §5 "Items").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationView {
    Unknown,
    Test,
    Live,
}

impl From<Classification> for ClassificationView {
    fn from(c: Classification) -> Self {
        match c {
            Classification::Unknown => ClassificationView::Unknown,
            Classification::Test => ClassificationView::Test,
            Classification::Live => ClassificationView::Live,
        }
    }
}

impl ClassificationView {
    pub fn as_str(self) -> &'static str {
        match self {
            ClassificationView::Unknown => "unknown",
            ClassificationView::Test => "test",
            ClassificationView::Live => "live",
        }
    }
}

/// One field of an item, never its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldView {
    pub name: String,
    /// Prior values kept, up to 3.
    pub prior_count: u8,
    pub created_secs: u64,
    pub updated_secs: u64,
}

/// Who owns or pays for an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountView {
    pub email: Option<String>,
    pub label: Option<String>,
    pub org_id: Option<String>,
}

/// What `show` adds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemDetailView {
    /// The provider's hosts when the item was made (SPEC §8).
    pub allowed_hosts: Vec<String>,
    pub tags: Vec<String>,
    pub links: LinksView,
    pub last_used_secs: Option<u64>,
    pub notes: Option<String>,
}

/// Provider pages for an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinksView {
    pub docs: Option<String>,
    pub billing: Option<String>,
    pub keys_page: Option<String>,
    pub dashboard: Option<String>,
}

/// How a value's length stands against the rules for injection (SPEC §6.1
/// step 6, gate 9): a bucket, never the length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LengthClass {
    /// 16 bytes or more.
    Ok,
    /// 8 to 15 bytes: injected only with `allow_short`, with coverage
    /// warnings.
    Short,
    /// Under 8 bytes: never injected.
    TooShort,
}

impl LengthClass {
    /// The bucket of a value of `len` bytes.
    pub fn of(len: usize) -> Self {
        match len {
            0..8 => LengthClass::TooShort,
            8..16 => LengthClass::Short,
            _ => LengthClass::Ok,
        }
    }
}

/// `items.add`: the item made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddedView {
    pub item: ItemView,
    /// The field that holds the value.
    pub field: String,
    /// The provider the value's shape says, when it is not the item's own
    /// (none was named and several match, or another was named).
    pub detected: Option<String>,
    /// Several providers' key patterns match the value; name one.
    pub ambiguous: bool,
    pub length: LengthClass,
}

/// `items.target`: what a `rotate` or `rm` would change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetView {
    pub item: ItemView,
    /// The field a rotation replaces: the one named, or the item's only
    /// field. `None` when none was named and the item has several.
    pub field: Option<String>,
    /// Grants in force that bind the item.
    pub grants: u64,
}

/// `items.rotate`: the value was replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotatedView {
    pub slug: String,
    pub field: String,
    /// Prior values now kept, the replaced one first.
    pub prior_count: u8,
    pub length: LengthClass,
    /// The item's classification now, detected from the new value as
    /// `items.add` detects it.
    pub classification: ClassificationView,
    /// Its classification before, when the new value changed it (SPEC
    /// §10b: a reclassification ends the grants that bind the item).
    pub reclassified_from: Option<ClassificationView>,
    /// Grants that bound it and ended: only a reclassification ends any.
    pub grants_ended: u64,
}

/// `items.remove`: the item is gone from the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovedView {
    pub slug: String,
    /// Grants that bound it and ended.
    pub grants_ended: u64,
    /// The file name of the encrypted backup written first, in the vault's
    /// `backups` directory; `envcloak recover` restores the vault from it,
    /// the removed item included.
    pub backup: String,
}

/// Whether a reference resolves (`envcloak_policy::BindErrorKind`, and
/// two of the checker's own).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefStatus {
    Ok,
    UnknownItem,
    UnknownField,
    AmbiguousField,
    NoField,
    CardReference,
    IssuerCredentialReference,
    UnknownItemClass,
    /// Not `NAME=<slug>[#field]`.
    InvalidReference,
    /// A name or reference shaped like a key rather than a name: most
    /// likely a value pasted in its place. Not shown.
    LooksLikeValue,
    /// Not checked: the daemon could not be asked.
    Unchecked,
}

impl RefStatus {
    pub fn is_ok(self) -> bool {
        self == RefStatus::Ok
    }
}

/// `items.check`: every binding of the manifest, and each reference sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckView {
    /// The project's canonical directory, when a manifest was sent.
    pub project_dir: Option<String>,
    pub project_name: Option<String>,
    /// `[env]` first, then each profile's own bindings.
    pub bindings: Vec<CheckBindingView>,
    /// One per reference sent, in order.
    pub refs: Vec<RefStatus>,
}

/// One binding of the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckBindingView {
    /// `None` for `[env]`.
    pub profile: Option<String>,
    /// `None` when it looks like a value ([`RefStatus::LooksLikeValue`]).
    pub env_name: Option<String>,
    /// `<slug>[#field]`; `None` when it looks like a value.
    pub reference: Option<String>,
    pub status: RefStatus,
}

/// `envcloak check`: the references, as the daemon found them, and the
/// project's env files, as the CLI read them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckReport {
    /// The manifest, when one was found.
    pub manifest: Option<String>,
    /// The daemon's answer; `None` when it could not be asked, or when
    /// there was nothing to ask ([`CheckReport::NOTHING_SENT`]).
    pub references: Option<CheckView>,
    /// Why the references were not checked: the error token of the
    /// connection or the daemon, or [`CheckReport::NOTHING_SENT`].
    pub unchecked: Option<String>,
    /// The env files read, at most `MAX_ENV_FILES` (64), in name order.
    pub env_files: Vec<EnvFileView>,
    /// Env files past that bound, which were not read: their plaintext
    /// keys and references are unknown.
    pub env_files_skipped: u64,
    /// Why the project directory's env files could not all be listed:
    /// [`CheckReport::DIRECTORY_UNREADABLE`] or
    /// [`CheckReport::LISTING_FAILED`]; `None` when the listing completed.
    /// After a failure `env_files` and `env_files_skipped` hold only what
    /// was seen before it, and how many more env files there are is
    /// unknown.
    #[serde(default)]
    pub env_scan_error: Option<String>,
}

impl CheckReport {
    /// The `unchecked` token when nothing was sent to the daemon: no
    /// manifest, and no reference in any env file.
    pub const NOTHING_SENT: &'static str = "no_manifest";

    /// `env_scan_error` when the project directory could not be opened or
    /// listed at all.
    pub const DIRECTORY_UNREADABLE: &'static str = "directory_unreadable";

    /// `env_scan_error` when the directory's listing broke off part way.
    pub const LISTING_FAILED: &'static str = "listing_failed";

    /// Whether everything checked out (docs/MANIFEST.md): every reference
    /// sent to the daemon resolves (none went unchecked, and a manifest's
    /// bindings all resolve), no env file holds a key-shaped value, and
    /// every env file was read: none left past the bound, and the
    /// directory listed in full (no `env_scan_error`). With nothing to
    /// send there is nothing unresolved; [`CheckReport::NOTHING_SENT`]
    /// beside an answer or an env file's reference is not that case.
    pub fn clean(&self) -> bool {
        !self.references_unchecked()
            && self.references.as_ref().is_none_or(|r| {
                r.bindings.iter().all(|b| b.status.is_ok()) && r.refs.iter().all(|s| s.is_ok())
            })
            && self.env_files.iter().all(EnvFileView::clean)
            && self.env_files_skipped == 0
            && self.env_scan_error.is_none()
    }

    /// Whether references were to be sent and the daemon did not answer
    /// for them: `unchecked` holds an error token, or
    /// [`CheckReport::NOTHING_SENT`] beside an answer or an env file's
    /// reference, which is not the nothing-to-send case it names.
    pub fn references_unchecked(&self) -> bool {
        match self.unchecked.as_deref() {
            None => false,
            Some(token) => {
                token != Self::NOTHING_SENT
                    || self.references.is_some()
                    || self.env_files.iter().any(|f| !f.references.is_empty())
            }
        }
    }
}

/// One env file in the project directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvFileView {
    /// Its name in the project directory.
    pub file: String,
    pub state: EnvFileState,
    /// A parse error's line (and kind, as a fixed message).
    pub error_line: Option<u32>,
    pub error: Option<String>,
    /// Ordinary variables whose value a provider's key pattern matches:
    /// plaintext keys, by line. Never the value.
    pub plaintext: Vec<PlaintextView>,
    /// `envcloak://` references, by line, and whether each resolves.
    pub references: Vec<EnvRefView>,
}

impl EnvFileView {
    pub fn clean(&self) -> bool {
        matches!(self.state, EnvFileState::Read)
            && self.plaintext.is_empty()
            && self.references.iter().all(|r| r.status.is_ok())
    }
}

/// What became of an env file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvFileState {
    Read,
    /// It does not parse; see `error`.
    Invalid,
    /// A symlink: never followed.
    Symlink,
    /// A FIFO, socket, device or directory.
    NotRegular,
    /// Owned by another user.
    NotOwned,
    /// Over 1 MiB.
    TooLarge,
    Unreadable,
}

/// A plaintext key in an env file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaintextView {
    pub line: u32,
    /// The variable; `None` when the name itself looks like a value.
    pub env_name: Option<String>,
    /// The provider, when one pattern alone matches.
    pub provider: Option<String>,
}

/// A reference in an env file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvRefView {
    pub line: u32,
    pub env_name: Option<String>,
    pub reference: Option<String>,
    pub status: RefStatus,
}

/// `envcloak ref`: what changed in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefEditView {
    /// The manifest's path.
    pub manifest: String,
    /// `None` for `[env]`.
    pub profile: Option<String>,
    pub env_name: String,
    pub reference: String,
    pub change: RefChange,
    /// The reference it had, when replaced.
    pub previous: Option<String>,
    /// Whether the vault has the item: `None` when it could not be asked.
    pub resolves: Option<RefStatus>,
}

/// What `envcloak ref` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefChange {
    Added,
    Replaced,
    /// The binding was there already.
    Unchanged,
}

/// Why an env-file entry is not imported (SPEC §6.4). It stays where it
/// is: `envcloak init --delete-plaintext` takes only the entries the vault
/// holds out of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    Empty,
    /// Under 8 bytes: never injected, so not a secret to keep (a port, a
    /// flag).
    TooShort,
    /// Configuration, not a secret: no provider's key pattern matches, the
    /// name says nothing of a secret, and the value is neither a URL with
    /// a password nor shaped like a generated key.
    NotSecret,
    /// It interpolates another variable (`${NAME}`), which is never
    /// expanded.
    Interpolated,
    /// An `envcloak://` reference already.
    Reference,
    /// The name is shaped like a key: a value pasted in its place.
    LooksLikeValue,
    /// Over the vault's 64 KiB field cap.
    TooLarge,
    /// It holds a NUL byte.
    NulByte,
    /// Under 16 characters with no provider's key shape, or a URL whose
    /// password is under 16 characters: short enough to guess, so it is
    /// imported and compared with the vault only for a person at a
    /// terminal with no agent (SPEC §6.5), and this caller is not told
    /// whether the vault holds it.
    Guessable,
}

impl SkipReason {
    pub fn token(self) -> &'static str {
        match self {
            SkipReason::Empty => "empty",
            SkipReason::TooShort => "too_short",
            SkipReason::NotSecret => "not_secret",
            SkipReason::Interpolated => "interpolated",
            SkipReason::Reference => "reference",
            SkipReason::LooksLikeValue => "looks_like_value",
            SkipReason::TooLarge => "too_large",
            SkipReason::NulByte => "nul_byte",
            SkipReason::Guessable => "guessable",
        }
    }
}

/// `import.plan` and `import.commit`: what the import does, or did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportPlanView {
    /// SHA-256 over the plan, as 64 hex characters: `import.commit` is
    /// refused unless the plan worked out then has this digest.
    pub digest: String,
    /// One per entry sent, in order.
    pub entries: Vec<ImportEntryView>,
    /// The items the import makes or binds to, in the order entries first
    /// use them.
    pub items: Vec<ImportItemView>,
}

/// What becomes of one entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportEntryView {
    /// Index into [`ImportPlanView::items`]; `None` when it is left out.
    pub item: Option<u32>,
    pub skipped: Option<SkipReason>,
}

/// One item an import makes, or finds holding the value already.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportItemView {
    pub slug: String,
    pub field: String,
    /// What a manifest binds: `<slug>`, or `<slug>#<field>` when the item
    /// has several fields.
    pub reference: String,
    /// The vault held the value before this import.
    pub existing: bool,
    pub provider: Option<String>,
    pub classification: ClassificationView,
    pub length: LengthClass,
    /// Every item that held the value before this import, by slug, the one
    /// bound first. More than one is a value with duplicate owners (gate
    /// 10), reported for each.
    pub holders: Vec<String>,
    /// Entries that use it, and in how many projects.
    pub entries: u32,
    pub projects: u32,
}

/// `import.verify`: whether an import's env files may be deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyView {
    /// The Recovery Kit is confirmed (`envcloak recovery confirm`).
    pub recovery_confirmed: bool,
    /// Every binding of the manifest, in `[env]` and each profile,
    /// resolves.
    pub resolves: bool,
    pub files: Vec<VerifyFileView>,
}

impl VerifyView {
    /// Whether every condition the daemon checks holds for every file.
    pub fn deletable(&self) -> bool {
        self.recovery_confirmed && self.resolves && self.files.iter().all(|f| f.covered)
    }
}

/// One file's entries, as the vault holds them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyFileView {
    pub file: String,
    /// Every secret it holds is in the vault where the manifest binds its
    /// variable.
    pub covered: bool,
    pub entries: Vec<VerifyEntryView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyEntryView {
    pub line: u32,
    /// `None` when it looks like a value.
    pub name: Option<String>,
    pub status: EntryStatus,
    /// Why it is left out, for [`EntryStatus::LeftOut`].
    pub skipped: Option<SkipReason>,
}

/// Where the vault stands on one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    /// The item the manifest binds the variable to holds this value.
    Stored,
    /// Not imported: it stays in the file (the reason is in `skipped`).
    LeftOut,
    /// A secret the vault does not hold where the manifest binds it: the
    /// file is not deleted.
    NotStored,
}

/// `files.backup`: the backup written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileBackupView {
    /// 26 Crockford base32 characters: `envcloak init --undo <id>`.
    pub id: String,
    pub files: u32,
    /// The backup's file name in the vault's `backups` directory.
    pub file_name: String,
}

/// `recovery.confirm`: the Recovery Kit is confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryConfirmedView {
    /// It was confirmed before.
    pub already: bool,
}

/// `backup.create`: the encrypted backup of the vault written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupView {
    /// The backup's absolute path, in the vault's `backups` directory:
    /// `envcloak recover --backup <path>` restores the vault from it.
    pub path: String,
    /// Its file name there.
    pub file_name: String,
    pub items: u64,
    /// The file's size in bytes.
    pub bytes: u64,
    /// When it was made, Unix seconds.
    pub created_secs: u64,
}

/// `vault.recover`: the vault is the one the backup held, under the new
/// passphrase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredView {
    /// The items the restored vault holds.
    pub items: u64,
    /// When the backup was made, Unix seconds.
    pub backup_created_secs: u64,
    /// The files moved out of its way (the replaced vault, kept as
    /// `vault/replaced-<time>.db`, and its side files); 0 when there was
    /// no vault.
    pub replaced: u64,
    /// A lock (a request, sleep or a signal) arrived while the backup was
    /// restored: the vault is the restored one, locked.
    pub locked: bool,
}

/// `envcloak init` and `envcloak import`: what was found, what the vault
/// does with it, and what was written. Names, paths, lines and slugs only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportReport {
    /// The directory scanned.
    pub root: String,
    /// The import was carried out; otherwise this is the dry run.
    pub committed: bool,
    pub projects: Vec<ProjectReport>,
    /// As the daemon planned them; `None` when nothing was sent.
    pub items: Vec<ImportItemView>,
    /// Paths the scan did not read, and why.
    pub skipped: Vec<SkippedPath>,
}

/// One directory with env files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectReport {
    pub dir: String,
    pub name: String,
    pub files: Vec<FileReport>,
    pub manifest: Option<FileChange>,
    /// Variables the manifest binds to other items already: kept as they
    /// are.
    pub conflicts: Vec<String>,
    pub gitignore: Option<FileChange>,
    /// The dry run of the manifest's references after the import: every
    /// one resolves.
    pub resolves: Option<bool>,
}

/// What an import did to a file it writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChange {
    Created,
    Updated,
    Unchanged,
    /// Left alone: a symlink, a hard link, or it changed while it was
    /// edited.
    Refused,
}

/// One env file read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileReport {
    /// Relative to the project's directory.
    pub file: String,
    pub profile: Option<String>,
    /// A template (`.env.example`): names only, no values read.
    pub template: bool,
    /// Another hard link names it: never modified or deleted.
    pub hard_linked: bool,
    /// A parse error: its line and kind.
    pub error_line: Option<u32>,
    pub error: Option<String>,
    pub entries: Vec<EntryReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryReport {
    pub line: u32,
    /// `None` when it looks like a value.
    pub name: Option<String>,
    /// Index into [`ImportReport::items`].
    pub item: Option<u32>,
    pub skipped: Option<SkipReason>,
}

/// A path the scan did not read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkippedPath {
    pub path: String,
    /// A token: `symlink`, `not_regular`, `too_large`, `unreadable`, ...
    pub reason: String,
}

/// `envcloak init --delete-plaintext`: the gate's answer, and what was
/// deleted. Only the entries the vault holds leave a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteReport {
    pub project_dir: String,
    /// The project's `.gitignore`, made to ignore the env files and every
    /// temporary name a change of one may leave plaintext under before
    /// any file changes; `refused` stops the deletion. `None` when there
    /// was no env file to delete.
    pub gitignore: Option<FileChange>,
    /// The daemon's answer, each file's entries in order, with the
    /// interpolated and reference entries the CLI never sent added as
    /// [`EntryStatus::LeftOut`].
    pub verify: VerifyView,
    /// The encrypted backup's id, once one was written.
    pub backup: Option<String>,
    /// Files deleted: the vault holds every entry.
    pub removed: Vec<String>,
    /// Files rewritten to hold only the entries the vault does not (the
    /// entries in `verify` that are not stored), as they were.
    pub rewritten: Vec<String>,
    /// Files the vault holds none of the entries of: left as they are.
    pub unchanged: Vec<String>,
    /// Files left in place, and why (a token).
    pub kept: Vec<SkippedPath>,
    /// Hard-linked, symlinked or unreadable env files never considered.
    pub skipped: Vec<SkippedPath>,
}

/// `envcloak init --undo`: the files written back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoReport {
    pub backup: String,
    pub files: Vec<UndoFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoFile {
    pub path: String,
    /// `restored`, `unchanged` (it is there as it was), or why it was not
    /// written (`exists`, `symlink`, ...).
    pub state: String,
}

/// `envcloak init`: the import, when there was one, and the deletion,
/// when it was asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitReport {
    /// What was found and imported; `None` for `--delete-plaintext` alone.
    pub import: Option<ImportReport>,
    pub delete: Option<DeleteReport>,
}
