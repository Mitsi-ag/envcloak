//! Pending requests (SPEC §10b "Approval proofs"): a request no grant
//! covers, held in daemon memory until a person approves or denies it, or
//! [`PENDING_TTL`] passes.
//!
//! A [`Pending`] keeps the [`AccessRequest`] as the daemon built it (the
//! evidence, the project, the bound items) and the [`PendingDescriptor`]
//! an approval surface receives, made at creation. What follows the vault
//! (each binding's classification, and the test items proposed for live
//! ones) is built again from the vault each time the request is shown and
//! when it is approved ([`Pending::current`], L-09), and the digest is
//! taken over that: a statement read before either changed does not
//! approve the request as it is now (`statement_mismatch`). The daemon nonce is
//! 32 random bytes; the id is 8 Crockford base32 characters, unique among
//! the pending requests and the outcomes remembered (the store draws again
//! on a clash).
//!
//! **Waiting** (SPEC §6.1 step 4, M2 plan D-04). No client waits for a
//! person on an open connection: `envcloak run --wait` asks for its
//! request's [`PendingState`] on fresh connections. So that a waiter whose
//! request was approved, denied or expired a moment ago is told so, the
//! store remembers each ended request's outcome and its root for
//! [`OUTCOME_TTL`], at most [`MAX_OUTCOMES`] of them (`Outcomes`). A
//! state is answered only to a caller whose kernel-verified chain holds
//! the request's root instance; anyone else, and anyone asking about an
//! id the store does not know, is told [`PendingState::Unknown`], so the
//! answer says nothing about another tree's requests. Forgetting an
//! outcome early (the oldest goes when the list is full) only makes its
//! waiter ask `run.request` again, which the grant store answers as the
//! outcome would have: a grant covers it, a denial is remembered for 10
//! minutes (`repeated`), and an expired request is opened anew.
//!
//! Polls are limited per subject root by a token bucket (`PollLimiter`)
//! that refills [`POLLS_PER_REQUEST`] per second for each live pending
//! request of the root (at least one's worth, so a root whose request just
//! ended can still read its outcome), and holds one second's worth. A poll
//! over the limit is refused ([`Busy`]), which a waiter answers by backing
//! off, never as a refusal. A bucket's clock only moves forward, so polls
//! that reach it out of order never refill an interval twice.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use envcloak_core::vault::{Classification, ItemMeta};
use serde::{Deserialize, Serialize};

use crate::effective::SubjectKind;
use crate::evidence::ProcessInstance;
use crate::grants::{AccessRequest, Now};
use crate::ids;
use crate::statement::{
    BindingSummary, PendingDescriptor, ProcessSummary, ProjectSummary, SubjectSummary, proposals,
};

/// How long a pending request waits for an approval.
pub const PENDING_TTL: Duration = Duration::from_secs(600);

/// How long an ended request's outcome is remembered: as long as a
/// request waits, so a waiter that asks at any point of its wait (at most
/// [`PENDING_TTL`]) is told how its request ended.
pub const OUTCOME_TTL: Duration = PENDING_TTL;

/// Outcomes remembered at once; the oldest is forgotten to make room (see
/// the module documentation for why that is safe).
pub const MAX_OUTCOMES: usize = 256;

/// Polls one root may make each second for each of its live pending
/// requests (SPEC §10a allows 3 per root, so at most 12 a second).
pub const POLLS_PER_REQUEST: u32 = 4;

/// Roots whose poll budget is kept at once. A root whose bucket has
/// been left alone for a second is full again and needs no entry; past
/// this many busy ones, a new root's poll is refused ([`Busy`]) rather
/// than another root's budget forgotten.
pub const MAX_POLL_ROOTS: usize = 1024;

/// How a request stands, as `pending.state` answers it (SPEC §6.1 step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingState {
    /// Waiting for a person's approval.
    Pending,
    /// A person approved it: the request asked again is covered.
    Approved,
    /// A person denied it.
    Denied,
    /// It was neither approved nor denied within [`PENDING_TTL`].
    Expired,
    /// No request with this id belongs to the caller's process tree: none
    /// has the id, it belongs to another tree, or its outcome is no longer
    /// remembered. Asking `run.request` again tells the caller where it
    /// stands.
    Unknown,
}

impl PendingState {
    /// The word on the wire and in output.
    pub fn word(self) -> &'static str {
        match self {
            PendingState::Pending => "pending",
            PendingState::Approved => "approved",
            PendingState::Denied => "denied",
            PendingState::Expired => "expired",
            PendingState::Unknown => "unknown",
        }
    }
}

/// A poll over its root's limit: the caller backs off and asks again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Busy;

/// How a request ended, and whose it was.
#[derive(Debug, Clone)]
struct Ended {
    root: ProcessInstance,
    state: PendingState,
    /// Awake time when it ended.
    at: Duration,
}

/// The outcomes of requests that ended, for their waiters.
#[derive(Debug, Clone, Default)]
pub(crate) struct Outcomes {
    ended: BTreeMap<PendingId, Ended>,
}

impl Outcomes {
    /// Records that request `id` of `root` ended in `state` at `now`.
    pub(crate) fn record(
        &mut self,
        id: PendingId,
        root: ProcessInstance,
        state: PendingState,
        now: &Now,
    ) {
        self.expire(now);
        if self.ended.len() >= MAX_OUTCOMES && !self.ended.contains_key(&id) {
            let oldest = self
                .ended
                .iter()
                .min_by_key(|(_, e)| e.at)
                .map(|(id, _)| *id);
            if let Some(oldest) = oldest {
                self.ended.remove(&oldest);
            }
        }
        self.ended.insert(
            id,
            Ended {
                root,
                state,
                at: now.awake,
            },
        );
    }

    /// Forgets outcomes older than [`OUTCOME_TTL`].
    pub(crate) fn expire(&mut self, now: &Now) {
        self.ended
            .retain(|_, e| now.awake.saturating_sub(e.at) < OUTCOME_TTL);
    }

    /// The outcome of `id`, and the root it belongs to.
    pub(crate) fn get(&self, id: &PendingId) -> Option<(&ProcessInstance, PendingState)> {
        self.ended.get(id).map(|e| (&e.root, e.state))
    }

    pub(crate) fn contains(&self, id: &PendingId) -> bool {
        self.ended.contains_key(id)
    }

    pub(crate) fn len(&self) -> usize {
        self.ended.len()
    }

    pub(crate) fn clear(&mut self) {
        self.ended.clear();
    }
}

/// Units of a bucket's budget in one poll: a bucket counts in billionths
/// of a poll, so that every nanosecond of refill counts, however close
/// together the polls come.
const NANO: u128 = 1_000_000_000;

/// One root's poll budget, in billionths of a poll ([`NANO`]).
#[derive(Debug, Clone, Copy)]
struct Bucket {
    nano: u128,
    /// Awake time of the latest poll: what is refilled up to.
    at: Duration,
}

/// The per-root poll limit of `pending.state` (see the module
/// documentation).
#[derive(Debug, Clone, Default)]
pub(crate) struct PollLimiter {
    buckets: HashMap<ProcessInstance, Bucket>,
}

impl PollLimiter {
    /// Takes one poll for `root`, which has `live` pending requests, at
    /// awake time `now`.
    ///
    /// # Errors
    /// [`Busy`] when the root's bucket is empty, or when
    /// [`MAX_POLL_ROOTS`] other roots have polled within the last second.
    pub(crate) fn take(
        &mut self,
        root: &ProcessInstance,
        live: usize,
        now: Duration,
    ) -> Result<(), Busy> {
        // One second's worth, refilled in one second: `per_second` units
        // for each nanosecond.
        let per_second =
            u128::from(POLLS_PER_REQUEST) * u128::try_from(live.max(1)).unwrap_or(u128::MAX);
        let cap = per_second.saturating_mul(NANO);
        if !self.buckets.contains_key(root) && self.buckets.len() >= MAX_POLL_ROOTS {
            // A bucket left alone for a second is full again: forget it.
            self.buckets
                .retain(|_, b| now.saturating_sub(b.at) < Duration::from_secs(1));
            if self.buckets.len() >= MAX_POLL_ROOTS {
                return Err(Busy);
            }
        }
        let b = self
            .buckets
            .entry(root.clone())
            .or_insert(Bucket { nano: cap, at: now });
        // The bucket's clock never moves back: polls whose times were read
        // before the store's lock can arrive out of order, and an earlier
        // time taken as the bucket's would refill the same interval twice.
        // Every nanosecond it moves is refilled, refused polls' included:
        // none is dropped, however close together the polls come.
        let elapsed = now.saturating_sub(b.at).as_nanos();
        b.nano = b
            .nano
            .saturating_add(elapsed.saturating_mul(per_second))
            .min(cap);
        b.at = b.at.max(now);
        if b.nano < NANO {
            return Err(Busy);
        }
        b.nano -= NANO;
        Ok(())
    }

    /// How many roots' buckets are kept.
    pub(crate) fn roots(&self) -> usize {
        self.buckets.len()
    }

    pub(crate) fn clear(&mut self) {
        self.buckets.clear();
    }
}

/// A request id: 40 random bits, shown as 8 Crockford base32 characters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingId([u8; 5]);

impl PendingId {
    /// A random id. The store makes sure it is unique among the pending
    /// requests.
    pub fn generate() -> Self {
        PendingId(ids::random())
    }

    /// Parses the 8-character form, in either case, with Crockford's
    /// aliases (`I`, `L` as `1`; `O` as `0`).
    pub fn parse(s: &str) -> Option<Self> {
        let mut b = [0u8; 5];
        ids::decode(s, 8, &mut b)?;
        Some(PendingId(b))
    }
}

impl core::fmt::Display for PendingId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&ids::encode(&self.0, 8))
    }
}

impl core::fmt::Debug for PendingId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PendingId({self})")
    }
}

/// A request waiting for an approval.
#[derive(Debug, Clone)]
pub struct Pending {
    pub id: PendingId,
    pub nonce: [u8; 32],
    pub request: AccessRequest,
    /// What the approver receives; its digest is what the proof covers.
    pub descriptor: PendingDescriptor,
    /// The request's identity for flood control.
    pub fingerprint: [u8; 32],
    /// Awake time when it was opened.
    pub opened: Duration,
}

impl Pending {
    /// Opens `request` as pending request `id` at `now`. `granted` says,
    /// binding by binding, whether a session grant in force already covers
    /// it.
    pub(crate) fn open(
        id: PendingId,
        request: AccessRequest,
        fingerprint: [u8; 32],
        granted: &[bool],
        now: &Now,
    ) -> Self {
        let nonce: [u8; 32] = ids::random();
        let descriptor = describe(id, &nonce, &request, granted, now);
        Pending {
            id,
            nonce,
            request,
            descriptor,
            fingerprint,
            opened: now.awake,
        }
    }

    /// The descriptor as an approval surface receives it now, from
    /// `items`, the vault's metadata now (L-09): each binding's
    /// classification read from its item, and the test items proposed for
    /// the live ones ([`proposals`]); the rest as it was made at creation.
    /// `None` when a bound item is gone (its removal ends the request, so
    /// a vault that lacks one is not the vault the request was made
    /// from).
    pub fn current(&self, items: &[ItemMeta]) -> Option<PendingDescriptor> {
        let mut d = self.descriptor.clone();
        for (shown, b) in d.bindings.iter_mut().zip(&self.request.bindings) {
            let item = items.iter().find(|m| m.id == b.binding.item)?;
            shown.classification = classification_word(item.details.classification).to_owned();
        }
        d.proposals = proposals(&self.request.bindings, items);
        Some(d)
    }

    /// Whether the request has expired at `now`.
    pub fn expired(&self, now: &Now) -> bool {
        now.awake.saturating_sub(self.opened) >= PENDING_TTL
    }

    /// How long it has waited at `now`, in awake time.
    pub fn age(&self, now: &Now) -> Duration {
        now.awake.saturating_sub(self.opened)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The word for an item's classification.
pub(crate) fn classification_word(c: Classification) -> &'static str {
    match c {
        Classification::Test => "test",
        Classification::Live => "live",
        Classification::Unknown => "unknown",
    }
}

/// The descriptor an approval surface receives for `r`.
fn describe(
    id: PendingId,
    nonce: &[u8; 32],
    r: &AccessRequest,
    granted: &[bool],
    now: &Now,
) -> PendingDescriptor {
    let root = r.subject.root();
    let kind = r.subject.kind();
    let label = match kind {
        SubjectKind::Agent => r.subject.label().map(|l| l.name.clone()),
        SubjectKind::Terminal | SubjectKind::Unknown => None,
    };
    PendingDescriptor {
        request: id.to_string(),
        nonce: hex(nonce),
        created_secs: now
            .wall
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        expires_in_secs: PENDING_TTL.as_secs(),
        subject: SubjectSummary {
            kind,
            label,
            caller_pid: r.subject.caller().pid,
            root: ProcessSummary {
                pid: root.pid,
                start_time: root.start_time.raw(),
                exe: root
                    .exe
                    .as_ref()
                    .map(|e| e.path.to_string_lossy().into_owned()),
            },
        },
        project: ProjectSummary {
            dir: r.project.canonical_dir.to_string_lossy().into_owned(),
            manifest: r.project.manifest_path.to_string_lossy().into_owned(),
            manifest_sha256: hex(&r.manifest_sha256),
            new_project: r.new_project,
        },
        bindings: r
            .bindings
            .iter()
            .enumerate()
            .map(|(k, b)| BindingSummary {
                env_name: b.binding.env_name.as_str().to_owned(),
                slug: b.slug.as_str().to_owned(),
                item: b.binding.item.to_string(),
                field: b.binding.field.to_string(),
                field_name: b.field_name.as_str().to_owned(),
                classification: classification_word(b.binding.classification).to_owned(),
                first_use: b.first_use,
                granted: granted.get(k).copied().unwrap_or(false),
            })
            .collect(),
        // Built from the vault each time the request is shown or approved
        // (`Pending::current`).
        proposals: Vec::new(),
        mode: r.mode,
        argv: r.argv_display.clone(),
    }
}
