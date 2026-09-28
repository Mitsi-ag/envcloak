//! Pending requests (SPEC §10b "Approval proofs"): a request no grant
//! covers, held in daemon memory until a person approves or denies it, or
//! [`PENDING_TTL`] passes.
//!
//! A [`Pending`] keeps the [`AccessRequest`] as the daemon built it (the
//! evidence, the project, the bound items) and the [`PendingDescriptor`]
//! an approval surface receives, made once at creation so that what the
//! approver sees is what the daemon's digest covers. The daemon nonce is
//! 32 random bytes; the id is 8 Crockford base32 characters, unique among
//! the pending requests (the store draws again on a clash).

use std::time::Duration;

use envcloak_core::vault::Classification;

use crate::effective::SubjectKind;
use crate::grants::{AccessRequest, Now};
use crate::ids;
use crate::statement::{
    BindingSummary, PendingDescriptor, ProcessSummary, ProjectSummary, SubjectSummary,
};

/// How long a pending request waits for an approval.
pub const PENDING_TTL: Duration = Duration::from_secs(600);

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

    /// Whether the request has expired at `now`.
    pub fn expired(&self, now: &Now) -> bool {
        now.awake.saturating_sub(self.opened) >= PENDING_TTL
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
        mode: r.mode,
        argv: r.argv_display.clone(),
    }
}
