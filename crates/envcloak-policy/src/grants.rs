//! Grants and the decisions they give (SPEC §10b; gates 23 and 27 to 32).
//!
//! The [`GrantStore`] lives in the daemon's memory, under its state lock,
//! and is never persisted or synced. It answers one question for every
//! request ([`GrantStore::decide`]): is the request covered by a grant, is
//! it pending a person's approval, or is it denied? A grant is created
//! only by [`GrantStore::approve`], from a pending request, with an
//! [`ApprovalProof`] the daemon verified (the passphrase) and the digest
//! of the statement the approver read.
//!
//! **Match** (SPEC §10b). Request R is covered by grant G only if:
//! 1. G is not expired (either deadline: wall clock or awake time),
//!    revoked or used up;
//! 2. the vault is unlocked at G's epochs (the store is cleared at lock,
//!    and a policy epoch bump ends older grants);
//! 3. and 4. G's root is in R's kernel-verified ancestry with its pid and
//!    start time, and no known agent sits between them unless the root is
//!    that agent; a terminal grant covers only terminal subjects
//!    ([`SubjectEvidence::covered_by`]);
//! 5. R's project identity (canonical directory, device, inode) equals
//!    G's;
//! 6. R's bindings are a subset of G's, by (env name, item id, field id);
//! 7. R's mode is at least as strict as G's.
//!
//! A manifest change that leaves the bindings a subset does not prompt;
//! the daemon audits the new hash. Any added or changed binding prompts
//! for the difference: the statement asks for the bindings no grant in
//! force for the caller and project covers, and lists the ones a session
//! grant already covers apart, since the new grant holds the whole
//! request.
//!
//! **Lifetimes.** Grants last [`DEFAULT_TTL`] by default; agent grants
//! [`MAX_AGENT_TTL`] at most, and terminal and unknown ones
//! [`MAX_TERMINAL_TTL`] at most: missing evidence takes the tighter
//! bound. Both a wall-clock and an awake-time
//! deadline are set at approval and either ends the grant, so a clock
//! stepped either way cannot lengthen one. A grant never outlives its root
//! process: [`GrantStore::sweep`] drops grants whose root is gone. Lock
//! ([`GrantStore::on_lock`]) drops every grant and pending request; sleep
//! locks; a daemon restart starts empty.
//!
//! **Once.** A `once` grant covers exactly one request: the daemon decides
//! and consumes under one lock ([`GrantStore::consume`]), so of concurrent
//! requests exactly one is covered. When a session grant covers the same
//! request, it is preferred and the once grant is kept.
//!
//! **Bounds.** [`crate::flood`] holds the pending caps and the denial
//! rules; at most [`MAX_GRANTS`] grants exist at a time.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use envcloak_core::vault::{FieldId, FieldName, ItemId, Slug};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bind::BoundBinding;
use crate::effective::SubjectKind;
use crate::evidence::{ProcessInstance, SubjectEvidence};
use crate::flood::{FloodControl, MAX_PENDING, MAX_PENDING_PER_ROOT};
use crate::ids;
use crate::manifest::Mode;
use crate::names::EnvName;
use crate::pending::{Pending, PendingId};
use crate::project::ProjectIdentity;
use crate::statement::{PendingDescriptor, statement_digest};

/// A session grant's length when the approver names none.
pub const DEFAULT_TTL: Duration = Duration::from_secs(8 * 3600);
/// The longest grant for an agent subject.
pub const MAX_AGENT_TTL: Duration = Duration::from_secs(24 * 3600);
/// The longest grant for a terminal or unknown subject. An unknown subject
/// is one whose evidence is missing (an orphan, a service manager's job, a
/// caller without a terminal), so it takes the tighter of the two bounds.
pub const MAX_TERMINAL_TTL: Duration = Duration::from_secs(12 * 3600);
/// Grants held at once.
pub const MAX_GRANTS: usize = 256;

/// One reading of the clocks a decision needs: the wall clock (UTC), time
/// awake, and time including sleep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    pub wall: SystemTime,
    pub awake: Duration,
    pub including_sleep: Duration,
}

/// A grant's identifier: a ULID, shown as 26 Crockford base32 characters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantId([u8; 16]);

impl GrantId {
    /// A new id: 48 bits of time in milliseconds, then 80 random bits.
    pub fn generate() -> Self {
        let ms = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let ms = u64::try_from(ms).unwrap_or(u64::MAX);
        let mut id = [0u8; 16];
        id[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
        id[6..].copy_from_slice(&ids::random::<10>());
        GrantId(id)
    }

    /// Parses the 26-character form, in either case.
    pub fn parse(s: &str) -> Option<Self> {
        let mut b = [0u8; 16];
        ids::decode(s, 26, &mut b)?;
        Some(GrantId(b))
    }
}

impl core::fmt::Display for GrantId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&ids::encode(&self.0, 26))
    }
}

impl core::fmt::Debug for GrantId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "GrantId({self})")
    }
}

/// How often a grant may be used (SPEC §10b `uses`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Uses {
    /// The next covered request, and no other.
    Once,
    /// Every covered request until the grant ends.
    Session,
}

/// What the approver chooses: `--once` or `--for <duration>`, and the
/// live bindings ticked (`--live NAME`; stored in M1, enforced in M2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalOptions {
    pub uses: Uses,
    /// The grant's length in seconds.
    pub ttl_secs: u64,
    /// The bindings whose live-classified values the approver allows.
    pub live: Vec<EnvName>,
}

impl ApprovalOptions {
    /// A session grant of `ttl`.
    pub fn session(ttl: Duration) -> Self {
        ApprovalOptions {
            uses: Uses::Session,
            ttl_secs: ttl.as_secs(),
            live: Vec::new(),
        }
    }

    /// A once grant, usable within `ttl`.
    pub fn once(ttl: Duration) -> Self {
        ApprovalOptions {
            uses: Uses::Once,
            ttl_secs: ttl.as_secs(),
            live: Vec::new(),
        }
    }
}

/// What kind of proof the daemon verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofKind {
    /// The vault passphrase, checked against the envelope (SPEC §10b).
    Passphrase,
}

/// A verified proof, and who gave it. The store refuses one from an
/// approver that may not give a proof
/// ([`SubjectEvidence::proof_refusal`]: an agent by any evidence, or no
/// terminal session), whatever the daemon checked.
#[derive(Debug, Clone)]
pub struct ApprovalProof {
    pub approver: SubjectEvidence,
    pub kind: ProofKind,
}

/// A binding as a request asks for it: bound to the vault's item, with
/// what an approval surface shows for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundRef {
    pub binding: BoundBinding,
    /// Display only; the grant records the ids.
    pub slug: Slug,
    pub field_name: FieldName,
    /// No adopted project uses the item yet (SPEC §6.4 "Adoption").
    pub first_use: bool,
}

/// A request as the daemon built it from the wire, the vault and the
/// kernel: the caller's evidence, the project it opened, the bindings it
/// bound, and the command line as display text.
#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub subject: SubjectEvidence,
    pub project: ProjectIdentity,
    pub manifest_sha256: [u8; 32],
    pub bindings: Vec<BoundRef>,
    /// The effective mode.
    pub mode: Mode,
    pub argv_display: Vec<String>,
    /// The vault has no record of the project (SPEC §6.4 "Adoption").
    pub new_project: bool,
}

/// One binding a grant covers (SPEC §10b `bindings`): item ids, never
/// slugs, so a renamed item stays covered and a re-created one does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantBinding {
    pub env_name: EnvName,
    pub item: ItemId,
    pub field: FieldId,
    /// Display only.
    pub slug: Slug,
    /// The approver allowed a live value here.
    pub live: bool,
}

/// A grant (SPEC §10b `Grant`).
#[derive(Debug, Clone)]
pub struct Grant {
    pub id: GrantId,
    /// The process instance the grant is scoped to.
    pub root: ProcessInstance,
    /// The subject's kind at approval; a terminal grant covers only
    /// terminal subjects.
    pub kind: SubjectKind,
    /// The agent's display name, when one is involved.
    pub label: Option<String>,
    pub project: ProjectIdentity,
    pub manifest_sha256: [u8; 32],
    pub bindings: Vec<GrantBinding>,
    pub mode: Mode,
    pub uses: Uses,
    pub created: SystemTime,
    pub not_after_wall: SystemTime,
    pub not_after_awake: Duration,
    pub vault_epoch: u32,
    pub policy_epoch: u64,
}

impl Grant {
    /// Seconds of awake time left before the grant expires.
    pub fn remaining(&self, now: &Now) -> Duration {
        let awake = self.not_after_awake.saturating_sub(now.awake);
        let wall = self
            .not_after_wall
            .duration_since(now.wall)
            .unwrap_or_default();
        awake.min(wall)
    }

    fn expired(&self, now: &Now) -> bool {
        now.wall >= self.not_after_wall || now.awake >= self.not_after_awake
    }

    /// Whether the grant covers `r` by rules 5 to 7 (the project, the
    /// bindings and the mode). Rules 3 and 4 are the evidence's.
    fn covers(&self, r: &AccessRequest) -> bool {
        self.covers_project_and_mode(r) && r.bindings.iter().all(|b| self.has_binding(b))
    }

    /// Rules 5 and 7: the same project, and a mode at least as strict.
    fn covers_project_and_mode(&self, r: &AccessRequest) -> bool {
        self.project == r.project && r.mode >= self.mode
    }

    /// Whether the grant holds binding `b`, by (env name, item id, field
    /// id).
    fn has_binding(&self, b: &BoundRef) -> bool {
        self.bindings.iter().any(|g| {
            g.env_name == b.binding.env_name
                && g.item == b.binding.item
                && g.field == b.binding.field
        })
    }
}

/// The store's answer to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// A grant covers it. A `once` grant is used up by
    /// [`GrantStore::consume`].
    Covered(GrantId),
    /// No grant covers it; a person must approve this pending request.
    Pending(PendingId),
    /// Refused without a prompt.
    Denied(DenyReason),
}

/// Why a request was denied without a prompt (SPEC §10a "Bounds").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenyReason {
    /// An identical request was denied in the last 10 minutes.
    Repeated,
    /// The root was denied 3 times in 10 minutes and is denied for 30.
    RootDenied,
    /// The root has 3 pending requests already.
    PendingPerRoot,
    /// The daemon has 20 pending requests already.
    PendingTotal,
    /// 64 requests were denied within their windows: no new request is
    /// opened until the oldest window ends, so none is forgotten early.
    DenialsFull,
    /// A grant covered the request, but its audit entry could not be
    /// written, so nothing was released (SPEC §6.1 step 5, gate 33). The
    /// daemon decides this one, never the grant store.
    AuditFailed,
}

impl DenyReason {
    /// The stable token.
    pub fn token(self) -> &'static str {
        match self {
            DenyReason::Repeated => "repeated",
            DenyReason::RootDenied => "root_denied",
            DenyReason::PendingPerRoot => "pending_per_root",
            DenyReason::PendingTotal => "pending_total",
            DenyReason::DenialsFull => "denials_full",
            DenyReason::AuditFailed => "audit_failed",
        }
    }

    /// The token's reason, or `None`.
    pub fn from_token(t: &str) -> Option<Self> {
        [
            DenyReason::Repeated,
            DenyReason::RootDenied,
            DenyReason::PendingPerRoot,
            DenyReason::PendingTotal,
            DenyReason::DenialsFull,
            DenyReason::AuditFailed,
        ]
        .into_iter()
        .find(|r| r.token() == t)
    }

    /// The fixed message.
    pub fn message(self) -> &'static str {
        match self {
            DenyReason::Repeated => "an identical request was denied in the last 10 minutes",
            DenyReason::RootDenied => {
                "this process tree was denied three times in 10 minutes and is denied for 30"
            }
            DenyReason::PendingPerRoot => {
                "this process tree already has 3 requests waiting for approval"
            }
            DenyReason::PendingTotal => "20 requests are already waiting for approval",
            DenyReason::DenialsFull => {
                "64 requests were denied in the last 10 minutes; new requests wait until the \
                 oldest of those denials is 10 minutes old"
            }
            DenyReason::AuditFailed => {
                "a grant covers this request, but its audit entry could not be written, so \
                 nothing was released; `envcloak status` and the daemon's log say more"
            }
        }
    }
}

/// Why an approval was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApproveError {
    /// No pending request has the id, or it expired.
    NoSuchRequest,
    /// The digest is not that of this request with these options.
    StatementMismatch,
    /// The approver may not give a proof
    /// ([`SubjectEvidence::proof_refusal`]).
    ProofRefused,
    InvalidOptions(OptionsError),
    /// [`MAX_GRANTS`] exist already.
    TooManyGrants,
}

/// What is wrong with the approval options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptionsError {
    TtlZero,
    /// Longer than the subject's kind allows.
    TtlTooLong,
    /// A `live` name is not among the request's bindings.
    LiveNotBound,
}

impl OptionsError {
    /// The stable token.
    pub fn token(self) -> &'static str {
        match self {
            OptionsError::TtlZero => "ttl_zero",
            OptionsError::TtlTooLong => "ttl_too_long",
            OptionsError::LiveNotBound => "live_not_bound",
        }
    }
}

/// Which grants to revoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeSelector {
    Id(GrantId),
    All,
}

/// What a denial did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenyOutcome {
    /// This denial was the third for the root within 10 minutes: the root
    /// is denied for 30 minutes.
    pub root_auto_denied: bool,
}

/// The error of [`GrantStore::deny`]: no such pending request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NoSuchRequest;

/// The grants and pending requests of one unlocked vault, and the flood
/// state that outlives it.
#[derive(Debug, Clone)]
pub struct GrantStore {
    grants: BTreeMap<GrantId, Grant>,
    pending: BTreeMap<PendingId, Pending>,
    flood: FloodControl,
    vault_epoch: u32,
    policy_epoch: u64,
}

impl Default for GrantStore {
    fn default() -> Self {
        Self::new()
    }
}

/// The identity of a request for flood control: SHA-256 over the root,
/// the project, the bindings (sorted), the mode and the command line.
fn fingerprint(r: &AccessRequest) -> [u8; 32] {
    let root = r.subject.root();
    let mut h = Sha256::new();
    let mut str = |s: &[u8]| {
        h.update(u32::try_from(s.len()).unwrap_or(u32::MAX).to_be_bytes());
        h.update(s);
    };
    str(&root.pid.to_be_bytes());
    str(&root.start_time.raw().to_be_bytes());
    str(r.project.canonical_dir.as_os_str().as_encoded_bytes());
    str(&r.project.dev.to_be_bytes());
    str(&r.project.ino.to_be_bytes());
    let mut keys: Vec<(&EnvName, &ItemId, &FieldId)> = r
        .bindings
        .iter()
        .map(|b| (&b.binding.env_name, &b.binding.item, &b.binding.field))
        .collect();
    keys.sort();
    for (env, item, field) in keys {
        str(env.as_str().as_bytes());
        str(item.as_bytes());
        str(field.as_bytes());
    }
    str(match r.mode {
        Mode::Inject => b"inject",
        Mode::Proxy => b"proxy",
    });
    for a in &r.argv_display {
        str(a.as_bytes());
    }
    h.finalize().into()
}

impl GrantStore {
    /// An empty store at epoch 0.
    pub fn new() -> Self {
        GrantStore {
            grants: BTreeMap::new(),
            pending: BTreeMap::new(),
            flood: FloodControl::new(),
            vault_epoch: 0,
            policy_epoch: 0,
        }
    }

    /// The vault's epochs at unlock. Grants of other epochs end.
    pub fn set_epochs(&mut self, vault_epoch: u32, policy_epoch: u64) {
        self.vault_epoch = vault_epoch;
        self.policy_epoch = policy_epoch;
        self.drop_stale_epochs();
    }

    /// A policy epoch bump (the user tightening vault policy): grants of
    /// the old epoch end.
    pub fn set_policy_epoch(&mut self, policy_epoch: u64) {
        self.policy_epoch = policy_epoch;
        self.drop_stale_epochs();
    }

    fn drop_stale_epochs(&mut self) {
        let (v, p) = (self.vault_epoch, self.policy_epoch);
        self.grants
            .retain(|_, g| g.vault_epoch == v && g.policy_epoch == p);
    }

    /// Drops what has expired at `now`.
    fn expire(&mut self, now: &Now) {
        self.grants.retain(|_, g| !g.expired(now));
        self.pending.retain(|_, p| !p.expired(now));
        self.flood.expire(now);
    }

    /// Whether grant `g` is in force at `now` for `r`'s caller: not
    /// expired, of the current epochs, and rooted where it may cover the
    /// caller (rules 1 to 4).
    fn in_force_for(&self, g: &Grant, r: &AccessRequest, now: &Now) -> bool {
        !g.expired(now)
            && g.vault_epoch == self.vault_epoch
            && g.policy_epoch == self.policy_epoch
            && r.subject.covered_by(&g.root, g.kind)
    }

    /// The grant that covers `r`, a session grant before a once grant.
    fn covering(&self, r: &AccessRequest, now: &Now) -> Option<GrantId> {
        let live = |g: &&Grant| self.in_force_for(g, r, now) && g.covers(r);
        self.grants
            .values()
            .filter(live)
            .find(|g| g.uses == Uses::Session)
            .or_else(|| self.grants.values().find(live))
            .map(|g| g.id)
    }

    /// For each binding of `r`, whether a session grant in force for its
    /// caller, project and mode already holds it: what the statement lists
    /// apart from the difference it asks for. A `once` grant does not
    /// count: it ends at its next use, so the new grant would be what
    /// holds the binding from then on.
    fn granted_bindings(&self, r: &AccessRequest, now: &Now) -> Vec<bool> {
        let grants: Vec<&Grant> = self
            .grants
            .values()
            .filter(|g| {
                g.uses == Uses::Session
                    && self.in_force_for(g, r, now)
                    && g.covers_project_and_mode(r)
            })
            .collect();
        r.bindings
            .iter()
            .map(|b| grants.iter().any(|g| g.has_binding(b)))
            .collect()
    }

    /// Decides `r` at `now`: covered, pending or denied. See the module
    /// documentation. An identical request already pending gets the same
    /// pending id.
    pub fn decide(&mut self, r: AccessRequest, now: &Now) -> Decision {
        self.expire(now);
        if let Some(g) = self.covering(&r, now) {
            return Decision::Covered(g);
        }
        let root = r.subject.root();
        let fp = fingerprint(&r);
        if self.flood.root_denied(&root, now) {
            return Decision::Denied(DenyReason::RootDenied);
        }
        if self.flood.recently_denied(&fp, now) {
            return Decision::Denied(DenyReason::Repeated);
        }
        if let Some(p) = self.pending.values().find(|p| p.fingerprint == fp) {
            return Decision::Pending(p.id);
        }
        let per_root = self
            .pending
            .values()
            .filter(|p| p.request.subject.root() == root)
            .count();
        if per_root >= MAX_PENDING_PER_ROOT {
            return Decision::Denied(DenyReason::PendingPerRoot);
        }
        if self.pending.len() >= MAX_PENDING {
            return Decision::Denied(DenyReason::PendingTotal);
        }
        // Every denial is kept for its whole window: with the list full,
        // no request is opened that a person could deny.
        if self.flood.full(now) {
            return Decision::Denied(DenyReason::DenialsFull);
        }
        let id = loop {
            let id = PendingId::generate();
            if !self.pending.contains_key(&id) {
                break id;
            }
        };
        let granted = self.granted_bindings(&r, now);
        self.pending
            .insert(id, Pending::open(id, r, fp, &granted, now));
        Decision::Pending(id)
    }

    /// The pending request `id`, unless it expired.
    pub fn pending(&self, id: &PendingId, now: &Now) -> Option<&Pending> {
        self.pending.get(id).filter(|p| !p.expired(now))
    }

    /// What an approval surface shows for pending request `id`.
    pub fn pending_descriptor(&self, id: &PendingId, now: &Now) -> Option<&PendingDescriptor> {
        self.pending(id, now).map(|p| &p.descriptor)
    }

    /// Everything [`GrantStore::approve`] checks apart from the proof, so
    /// a daemon can refuse before it runs Argon2id: the request exists,
    /// the options are within bounds, the digest is this request's with
    /// these options, and there is room for a grant.
    ///
    /// # Errors
    /// As [`GrantStore::approve`], except [`ApproveError::ProofRefused`].
    pub fn check_approval(
        &self,
        id: &PendingId,
        opts: &ApprovalOptions,
        digest: [u8; 32],
        now: &Now,
    ) -> Result<(), ApproveError> {
        let p = self.pending(id, now).ok_or(ApproveError::NoSuchRequest)?;
        let max = match p.request.subject.kind() {
            SubjectKind::Agent => MAX_AGENT_TTL,
            SubjectKind::Terminal | SubjectKind::Unknown => MAX_TERMINAL_TTL,
        };
        if opts.ttl_secs == 0 {
            return Err(ApproveError::InvalidOptions(OptionsError::TtlZero));
        }
        if opts.ttl_secs > max.as_secs() {
            return Err(ApproveError::InvalidOptions(OptionsError::TtlTooLong));
        }
        if opts
            .live
            .iter()
            .any(|l| !p.request.bindings.iter().any(|b| b.binding.env_name == *l))
        {
            return Err(ApproveError::InvalidOptions(OptionsError::LiveNotBound));
        }
        if statement_digest(&p.descriptor, opts) != digest {
            return Err(ApproveError::StatementMismatch);
        }
        if self.grants.len() >= MAX_GRANTS {
            return Err(ApproveError::TooManyGrants);
        }
        Ok(())
    }

    /// Approves pending request `id` with a verified `proof`, the
    /// approver's `opts` and the `digest` of the statement the approver
    /// read, creating a grant at `now`.
    ///
    /// # Errors
    /// [`ApproveError::NoSuchRequest`] for an unknown or expired id,
    /// [`ApproveError::ProofRefused`] when the approver may not give a
    /// proof ([`SubjectEvidence::proof_refusal`]),
    /// [`ApproveError::InvalidOptions`] for a length beyond the subject's
    /// bound or a live name not bound,
    /// [`ApproveError::StatementMismatch`] when `digest` is not that of
    /// this request with `opts`, [`ApproveError::TooManyGrants`] at the
    /// bound. The request stays pending on every error.
    pub fn approve(
        &mut self,
        id: &PendingId,
        proof: ApprovalProof,
        opts: ApprovalOptions,
        digest: [u8; 32],
        now: &Now,
    ) -> Result<GrantId, ApproveError> {
        self.expire(now);
        if self.pending(id, now).is_none() {
            return Err(ApproveError::NoSuchRequest);
        }
        if proof.approver.proof_refusal().is_some() {
            return Err(ApproveError::ProofRefused);
        }
        self.check_approval(id, &opts, digest, now)?;
        let p = self.pending.remove(id).ok_or(ApproveError::NoSuchRequest)?;
        let kind = p.request.subject.kind();
        let r = p.request;
        let ttl = Duration::from_secs(opts.ttl_secs);
        let id = loop {
            let id = GrantId::generate();
            if !self.grants.contains_key(&id) {
                break id;
            }
        };
        let grant = Grant {
            id,
            root: r.subject.root(),
            kind,
            label: r.subject.label().map(|l| l.name.clone()),
            project: r.project,
            manifest_sha256: r.manifest_sha256,
            bindings: r
                .bindings
                .into_iter()
                .map(|b| GrantBinding {
                    live: opts.live.contains(&b.binding.env_name),
                    env_name: b.binding.env_name,
                    item: b.binding.item,
                    field: b.binding.field,
                    slug: b.slug,
                })
                .collect(),
            mode: r.mode,
            uses: opts.uses,
            created: now.wall,
            not_after_wall: now.wall + ttl,
            not_after_awake: now.awake + ttl,
            vault_epoch: self.vault_epoch,
            policy_epoch: self.policy_epoch,
        };
        self.grants.insert(id, grant);
        Ok(id)
    }

    /// Uses grant `g` for one request: a `once` grant is removed, so a
    /// second call returns false; a session grant stays. False when the
    /// grant is gone.
    pub fn consume(&mut self, g: GrantId) -> bool {
        match self.grants.get(&g) {
            Some(grant) if grant.uses == Uses::Once => {
                self.grants.remove(&g);
                true
            }
            Some(_) => true,
            None => false,
        }
    }

    /// Revokes grants. Tightening needs no proof. Returns how many ended.
    pub fn revoke(&mut self, sel: RevokeSelector) -> usize {
        match sel {
            RevokeSelector::Id(id) => usize::from(self.grants.remove(&id).is_some()),
            RevokeSelector::All => {
                let n = self.grants.len();
                self.grants.clear();
                n
            }
        }
    }

    /// Denies pending request `id`: it is removed, and remembered for the
    /// flood rules.
    ///
    /// # Errors
    /// [`NoSuchRequest`] for an unknown or expired id.
    pub fn deny(&mut self, id: &PendingId, now: &Now) -> Result<DenyOutcome, NoSuchRequest> {
        self.expire(now);
        let p = self.pending.remove(id).ok_or(NoSuchRequest)?;
        let root_auto_denied =
            self.flood
                .record_denial(p.request.subject.root(), p.fingerprint, now);
        Ok(DenyOutcome { root_auto_denied })
    }

    /// Item `item` was deleted (SPEC §10b "A grant ends on"): every grant
    /// that binds it ends, and so does every pending request that asks for
    /// it, which would otherwise be approved into a grant for an item that
    /// is gone. Returns how many grants ended. An item created later under
    /// the same slug has another id, so nothing approved before covers it.
    pub fn on_item_removed(&mut self, item: ItemId) -> usize {
        let before = self.grants.len();
        self.grants
            .retain(|_, g| !g.bindings.iter().any(|b| b.item == item));
        self.pending
            .retain(|_, p| !p.request.bindings.iter().any(|b| b.binding.item == item));
        before - self.grants.len()
    }

    /// How many grants bind item `item`, for what `rm` says it will end.
    pub fn binding_item(&self, item: ItemId) -> usize {
        self.grants
            .values()
            .filter(|g| g.bindings.iter().any(|b| b.item == item))
            .count()
    }

    /// The vault locked: every grant and pending request ends. Denials
    /// and auto-denied roots stay.
    pub fn on_lock(&mut self) {
        self.grants.clear();
        self.pending.clear();
    }

    /// Drops what has expired, and every grant whose root `alive` says is
    /// gone.
    pub fn sweep(&mut self, now: &Now, alive: &dyn Fn(&ProcessInstance) -> bool) {
        self.expire(now);
        self.grants.retain(|_, g| alive(&g.root));
    }

    /// Grant `id`, if it exists.
    pub fn grant(&self, id: GrantId) -> Option<&Grant> {
        self.grants.get(&id)
    }

    /// Every grant, oldest first.
    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.values()
    }

    /// How many grants and unexpired pending requests there are.
    pub fn counts(&self, now: &Now) -> (usize, usize) {
        (
            self.grants.values().filter(|g| !g.expired(now)).count(),
            self.pending.values().filter(|p| !p.expired(now)).count(),
        )
    }

    /// The pending requests, oldest first, unexpired.
    pub fn pending_all(&self, now: &Now) -> impl Iterator<Item = &Pending> {
        self.pending.values().filter(move |p| !p.expired(now))
    }
}
