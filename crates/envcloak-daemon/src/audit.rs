//! Security events the daemon records (SPEC §3 principle 4, §4.3, §6.1
//! step 5, gates 22 and 33).
//!
//! Every event goes to the sealed, MAC-chained audit log
//! (`envcloak_core::audit`) and, as one value-free line, to the daemon's
//! standard error, which launchd and systemd keep. Every field of a line
//! is a fixed token or a number: a method name is recorded only through
//! [`envcloak_ipc::proto::loggable_method`], because a name a client sent
//! can hold anything. An entry holds more (the caller's kind and root, the
//! project, the items, the command line), all metadata; the command line
//! is masked before it gets here (`crate::redact`).
//!
//! [`AuditLog`] holds the writer while the vault is unlocked, since the
//! log's keys come from the vault key. Events that cannot be written (the
//! vault is locked, or the log's directory is unusable) wait in a bounded
//! queue, with a count of the ones it had no room for, and are written
//! first at the next chance. A delivery is different: its entry must be
//! on disk before anything is released, so it is written at once or the
//! request is denied ([`crate::state::State::audit_delivery`]).

use std::collections::VecDeque;
use std::time::Duration;

use envcloak_core::audit::{
    AuditError, AuditKind, AuditRecord, AuditWriter, DecisionSummary, OpenReport, ProjectSummary,
    SubjectSummary,
};
use envcloak_core::vault::{AuditHead, ItemId, Slug, Vault};
use envcloak_ipc::view::LockReason;

/// Events kept in memory while the log cannot be written.
pub const QUEUE_MAX: usize = 256;
/// The head is saved in the vault's header after this many entries.
pub const ANCHOR_EVERY: u64 = 100;
/// ... and after this long awake with entries not yet anchored.
pub const ANCHOR_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// A save that failed is tried again by a tick this long awake after it;
/// the wait doubles with each failure, up to [`ANCHOR_INTERVAL`].
pub const ANCHOR_RETRY_FIRST: Duration = Duration::from_secs(30);

/// A `run.request` decision, with what its entry records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestAudit {
    pub pid: i32,
    /// `covered`, `pending`, `denied` or `policy_denied`.
    pub decision: &'static str,
    pub request_id: Option<String>,
    pub grant_id: Option<String>,
    /// A `DenyReason` token, for `denied`.
    pub reason: Option<&'static str>,
    pub subject: SubjectSummary,
    pub project: Option<ProjectSummary>,
    pub items: Vec<(ItemId, Slug)>,
    /// The command line, masked (`crate::redact::redact_argv`).
    pub argv: Vec<String>,
}

/// An event worth recording. The ids in it are the daemon's own
/// (Crockford base32) and the tokens fixed; nothing a client sent but the
/// masked command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// A client-role peer called an `app`-role method.
    RoleDenied {
        method: &'static str,
        pid: i32,
        uid: u32,
    },
    /// A peer running as another uid connected; it was closed at accept.
    ForeignPeer { pid: i32, uid: u32 },
    /// A wrong passphrase was offered to `unlock`.
    UnlockFailed { pid: i32 },
    /// The vault was unlocked, or created (and unlocked).
    Unlocked { pid: i32, created: bool },
    /// The vault locked.
    Locked { reason: LockReason },
    /// A `run.request` was decided.
    Request(Box<RequestAudit>),
    /// A pending request was approved into a grant.
    Approved {
        pid: i32,
        request: String,
        grant: String,
        /// `once` or `session`.
        uses: &'static str,
        ttl_secs: u64,
    },
    /// An `approve` failed its proof.
    ApproveFailed { pid: i32, reason: &'static str },
    /// A proof was refused because of the caller's evidence, for the
    /// reason's token (`envcloak_policy::ProofRefusal::token`).
    ProofRefused {
        pid: i32,
        method: &'static str,
        reason: &'static str,
    },
    /// A pending request was denied.
    Denied {
        pid: i32,
        request: String,
        root_auto_denied: bool,
    },
    /// Grants were revoked.
    Revoked { pid: i32, count: usize },
    /// A covered request came with a manifest whose hash differs from the
    /// one at approval; the bindings were still a subset (SPEC §10b). The
    /// hashes are SHA-256 digests of the manifest's bytes, at approval and
    /// now.
    ManifestChanged {
        pid: i32,
        grant: String,
        dir: String,
        approved_sha256: [u8; 32],
        sha256: [u8; 32],
    },
    /// An item was added (`items.add`).
    Added {
        pid: i32,
        subject: SubjectSummary,
        item: ItemId,
        slug: Slug,
    },
    /// A value was replaced, with a proof (`items.rotate`).
    Rotated {
        pid: i32,
        subject: SubjectSummary,
        item: ItemId,
        slug: Slug,
        /// Prior values kept now.
        prior_count: u8,
        /// The classification before and after, when the new value changed
        /// it (`test`, `live`, `unknown`).
        reclassified: Option<(&'static str, &'static str)>,
        /// Grants that bound it and ended (only a reclassification ends
        /// any).
        grants: usize,
    },
    /// An item was removed, with a proof, after a backup (`items.remove`).
    Removed {
        pid: i32,
        subject: SubjectSummary,
        item: ItemId,
        slug: Slug,
        /// Grants that bound it and ended.
        grants: usize,
    },
    /// A rotation or removal failed its proof: the passphrase was wrong.
    /// `write` is [`AuditKind::Rotate`] or [`AuditKind::Remove`].
    ItemProofFailed {
        pid: i32,
        write: AuditKind,
        item: ItemId,
        slug: Slug,
    },
    /// A rotation or removal passed its proof and then changed nothing:
    /// the vault locked meanwhile (`vault_locked`), the backup could not be
    /// written (`backup_failed`), the target changed (`item_changed`), or
    /// the write failed (the vault's error token). Never
    /// `wrong_passphrase`, which is [`AuditEvent::ItemProofFailed`].
    ItemWriteFailed {
        pid: i32,
        subject: SubjectSummary,
        write: AuditKind,
        item: ItemId,
        slug: Slug,
        reason: &'static str,
    },
    /// Env-file values were imported (`import.commit`): the items made,
    /// and how many existing items were bound instead.
    Imported {
        pid: i32,
        subject: SubjectSummary,
        created: Vec<(ItemId, Slug)>,
        reused: usize,
    },
    /// Values were compared with the vault (`import.plan`,
    /// `import.commit`, `import.verify`), or refused for too many: the
    /// count of values, never one of them.
    ValuesChecked {
        pid: i32,
        subject: SubjectSummary,
        method: &'static str,
        values: usize,
        refused: bool,
    },
    /// An encrypted backup of files was written (`files.backup`).
    FilesBackedUp {
        pid: i32,
        subject: SubjectSummary,
        backup: String,
        files: usize,
    },
    /// A file backup was handed back, with a proof (`files.restore`).
    FilesRestored {
        pid: i32,
        subject: SubjectSummary,
        backup: String,
        files: usize,
    },
    /// The Recovery Kit was confirmed (`recovery.confirm`).
    RecoveryConfirmed {
        pid: i32,
        subject: SubjectSummary,
        already: bool,
    },
    /// A `files.restore`, `recovery.confirm` or `vault.recover` failed its
    /// proof: the passphrase or the kit was wrong. `kind` is
    /// [`AuditKind::FilesRestore`], [`AuditKind::RecoveryConfirm`] or
    /// [`AuditKind::Recover`].
    ProofFailed { pid: i32, kind: AuditKind },
    /// An encrypted backup of the vault was written (`backup.create`):
    /// the backup's id, in hex, and how many items it holds.
    BackedUp {
        pid: i32,
        backup: String,
        items: usize,
    },
    /// The vault was restored from an encrypted backup, with the kit as
    /// the proof (`vault.recover`): the backup's id, in hex, as the
    /// backup's own header says it, and how many items the vault holds.
    Recovered {
        pid: i32,
        subject: SubjectSummary,
        backup: String,
        items: usize,
    },
}

impl AuditEvent {
    /// The line for standard error, or `None` for events the daemon
    /// reports in its own words.
    pub fn line(&self) -> Option<String> {
        Some(match self {
            AuditEvent::RoleDenied { method, pid, uid } => format!(
                "envcloakd: audit: denied method={method} reason=role_denied role=client pid={pid} uid={uid}"
            ),
            AuditEvent::ForeignPeer { uid, .. } => {
                format!("envcloakd: audit: rejected connection reason=foreign_uid uid={uid}")
            }
            AuditEvent::UnlockFailed { pid } => {
                format!("envcloakd: audit: unlock failed reason=wrong_passphrase pid={pid}")
            }
            AuditEvent::Unlocked { .. } | AuditEvent::Locked { .. } => return None,
            AuditEvent::Request(r) => format!(
                "envcloakd: audit: request decision={} id={} pid={}",
                r.decision,
                r.grant_id
                    .as_deref()
                    .or(r.request_id.as_deref())
                    .or(r.reason)
                    .unwrap_or(""),
                r.pid
            ),
            AuditEvent::Approved {
                pid,
                request,
                grant,
                ..
            } => format!("envcloakd: audit: approved request={request} grant={grant} pid={pid}"),
            AuditEvent::ApproveFailed { pid, reason } => {
                format!("envcloakd: audit: approve failed reason={reason} pid={pid}")
            }
            AuditEvent::ProofRefused {
                pid,
                method,
                reason,
            } => {
                format!("envcloakd: audit: proof refused method={method} reason={reason} pid={pid}")
            }
            AuditEvent::Denied {
                pid,
                request,
                root_auto_denied,
            } => {
                let mut l = format!("envcloakd: audit: denied request={request} pid={pid}");
                if *root_auto_denied {
                    // The notification of SPEC §10a, until there is a
                    // surface for one (M3).
                    l.push_str(
                        "\nenvcloakd: notice: a process tree was denied three times in 10 minutes \
                         and is denied for 30",
                    );
                }
                l
            }
            AuditEvent::Revoked { pid, count } => {
                format!("envcloakd: audit: revoked grants={count} pid={pid}")
            }
            AuditEvent::ManifestChanged {
                pid,
                grant,
                approved_sha256,
                sha256,
                ..
            } => format!(
                "envcloakd: audit: manifest changed grant={grant} approved_sha256={} sha256={} \
                 pid={pid}",
                hex(approved_sha256),
                hex(sha256)
            ),
            AuditEvent::Added { pid, item, .. } => {
                format!("envcloakd: audit: item added id={item} pid={pid}")
            }
            AuditEvent::Rotated {
                pid,
                item,
                reclassified,
                grants,
                ..
            } => match reclassified {
                Some((from, to)) => format!(
                    "envcloakd: audit: item rotated id={item} reclassified={from}_to_{to} \
                     grants_ended={grants} pid={pid}"
                ),
                None => format!("envcloakd: audit: item rotated id={item} pid={pid}"),
            },
            AuditEvent::Removed {
                pid, item, grants, ..
            } => {
                format!("envcloakd: audit: item removed id={item} grants_ended={grants} pid={pid}")
            }
            AuditEvent::ItemProofFailed {
                pid, write, item, ..
            } => format!(
                "envcloakd: audit: {} failed reason=wrong_passphrase id={item} pid={pid}",
                write.token()
            ),
            AuditEvent::ItemWriteFailed {
                pid,
                write,
                item,
                reason,
                ..
            } => format!(
                "envcloakd: audit: {} failed reason={reason} id={item} pid={pid}",
                write.token()
            ),
            AuditEvent::Imported {
                pid,
                created,
                reused,
                ..
            } => format!(
                "envcloakd: audit: imported created={} reused={reused} pid={pid}",
                created.len()
            ),
            AuditEvent::ValuesChecked {
                pid,
                method,
                values,
                refused,
                ..
            } => format!(
                "envcloakd: audit: values {} method={method} values={values} pid={pid}",
                if *refused {
                    "refused reason=too_many_checks"
                } else {
                    "checked"
                }
            ),
            AuditEvent::FilesBackedUp {
                pid, backup, files, ..
            } => format!("envcloakd: audit: files backed up id={backup} files={files} pid={pid}"),
            AuditEvent::FilesRestored {
                pid, backup, files, ..
            } => format!("envcloakd: audit: files restored id={backup} files={files} pid={pid}"),
            AuditEvent::RecoveryConfirmed { pid, already, .. } => {
                format!("envcloakd: audit: recovery kit confirmed already={already} pid={pid}")
            }
            AuditEvent::ProofFailed { pid, kind } => format!(
                "envcloakd: audit: {} failed reason=wrong_secret pid={pid}",
                kind.token()
            ),
            AuditEvent::BackedUp { pid, backup, items } => {
                format!("envcloakd: audit: vault backed up id={backup} items={items} pid={pid}")
            }
            AuditEvent::Recovered {
                pid, backup, items, ..
            } => format!("envcloakd: audit: vault recovered id={backup} items={items} pid={pid}"),
        })
    }

    /// The log entry, made now.
    pub fn record(&self) -> AuditRecord {
        let subject = |pid: i32| SubjectSummary {
            pid,
            ..SubjectSummary::default()
        };
        match self {
            AuditEvent::RoleDenied { method, pid, .. } => AuditRecord {
                subject: subject(*pid),
                decision: decision("denied", Some("role_denied"), Some(method), None),
                ..AuditRecord::new(AuditKind::RoleDenied, "denied")
            },
            AuditEvent::ForeignPeer { pid, uid } => AuditRecord {
                subject: SubjectSummary {
                    pid: *pid,
                    uid: Some(*uid),
                    ..SubjectSummary::default()
                },
                decision: decision("rejected", Some("foreign_uid"), None, None),
                ..AuditRecord::new(AuditKind::ForeignPeer, "rejected")
            },
            AuditEvent::UnlockFailed { pid } => AuditRecord {
                subject: subject(*pid),
                decision: decision("failed", Some("wrong_passphrase"), None, None),
                ..AuditRecord::new(AuditKind::Unlock, "failed")
            },
            AuditEvent::Unlocked { pid, created } => AuditRecord {
                subject: subject(*pid),
                ..AuditRecord::new(
                    AuditKind::Unlock,
                    if *created { "created" } else { "unlocked" },
                )
            },
            AuditEvent::Locked { reason } => AuditRecord {
                decision: decision("locked", Some(reason.as_str()), None, None),
                ..AuditRecord::new(AuditKind::Lock, "locked")
            },
            AuditEvent::Request(r) => AuditRecord {
                request_id: r.request_id.clone(),
                grant_id: r.grant_id.clone(),
                subject: r.subject.clone(),
                project: r.project.clone(),
                items: r.items.clone(),
                decision: decision(r.decision, r.reason, Some("run.request"), None),
                argv_redacted: r.argv.clone(),
                ..AuditRecord::new(AuditKind::Run, r.decision)
            },
            AuditEvent::Approved {
                pid,
                request,
                grant,
                uses,
                ttl_secs,
            } => AuditRecord {
                request_id: Some(request.clone()),
                grant_id: Some(grant.clone()),
                subject: subject(*pid),
                decision: decision("approved", Some(uses), None, Some(*ttl_secs)),
                ..AuditRecord::new(AuditKind::Approve, "approved")
            },
            AuditEvent::ApproveFailed { pid, reason } => AuditRecord {
                subject: subject(*pid),
                decision: decision("failed", Some(reason), None, None),
                ..AuditRecord::new(AuditKind::Approve, "failed")
            },
            AuditEvent::ProofRefused {
                pid,
                method,
                reason,
            } => AuditRecord {
                subject: subject(*pid),
                decision: decision("refused", Some(reason), Some(method), None),
                ..AuditRecord::new(AuditKind::ProofRefused, "refused")
            },
            AuditEvent::Denied {
                pid,
                request,
                root_auto_denied,
            } => AuditRecord {
                request_id: Some(request.clone()),
                subject: subject(*pid),
                decision: decision(
                    "denied",
                    root_auto_denied.then_some("root_auto_denied"),
                    None,
                    None,
                ),
                ..AuditRecord::new(AuditKind::Deny, "denied")
            },
            AuditEvent::Revoked { pid, count } => AuditRecord {
                subject: subject(*pid),
                decision: decision(
                    "revoked",
                    None,
                    None,
                    Some(u64::try_from(*count).unwrap_or(u64::MAX)),
                ),
                ..AuditRecord::new(AuditKind::Revoke, "revoked")
            },
            AuditEvent::ManifestChanged {
                pid,
                grant,
                dir,
                approved_sha256,
                sha256,
            } => AuditRecord {
                grant_id: Some(grant.clone()),
                subject: subject(*pid),
                project: Some(ProjectSummary {
                    dir: dir.clone(),
                    manifest_sha256: *sha256,
                    approved_sha256: Some(*approved_sha256),
                }),
                ..AuditRecord::new(AuditKind::ManifestChanged, "covered")
            },
            AuditEvent::Added {
                subject,
                item,
                slug,
                ..
            } => AuditRecord {
                subject: subject.clone(),
                items: vec![(*item, slug.clone())],
                decision: decision("added", None, Some("items.add"), None),
                ..AuditRecord::new(AuditKind::Add, "added")
            },
            AuditEvent::Rotated {
                subject,
                item,
                slug,
                prior_count,
                reclassified,
                ..
            } => {
                // The reason names a reclassification: `reclassified_test_to_live`.
                let reason = reclassified.map(|(from, to)| format!("reclassified_{from}_to_{to}"));
                AuditRecord {
                    subject: subject.clone(),
                    items: vec![(*item, slug.clone())],
                    decision: decision(
                        "rotated",
                        reason.as_deref(),
                        Some("items.rotate"),
                        Some(u64::from(*prior_count)),
                    ),
                    ..AuditRecord::new(AuditKind::Rotate, "rotated")
                }
            }
            AuditEvent::Removed {
                subject,
                item,
                slug,
                grants,
                ..
            } => AuditRecord {
                subject: subject.clone(),
                items: vec![(*item, slug.clone())],
                decision: decision(
                    "removed",
                    None,
                    Some("items.remove"),
                    Some(u64::try_from(*grants).unwrap_or(u64::MAX)),
                ),
                ..AuditRecord::new(AuditKind::Remove, "removed")
            },
            AuditEvent::ItemProofFailed {
                pid,
                write,
                item,
                slug,
            } => AuditRecord {
                subject: subject(*pid),
                items: vec![(*item, slug.clone())],
                decision: decision("failed", Some("wrong_passphrase"), None, None),
                ..AuditRecord::new(*write, "failed")
            },
            AuditEvent::ItemWriteFailed {
                subject,
                write,
                item,
                slug,
                reason,
                ..
            } => AuditRecord {
                subject: subject.clone(),
                items: vec![(*item, slug.clone())],
                decision: decision("failed", Some(reason), None, None),
                ..AuditRecord::new(*write, "failed")
            },
            AuditEvent::Imported {
                subject,
                created,
                reused,
                ..
            } => AuditRecord {
                subject: subject.clone(),
                items: created.clone(),
                decision: decision(
                    "imported",
                    None,
                    Some("import.commit"),
                    Some(u64::try_from(*reused).unwrap_or(u64::MAX)),
                ),
                ..AuditRecord::new(AuditKind::Import, "imported")
            },
            AuditEvent::ValuesChecked {
                subject,
                method,
                values,
                refused,
                ..
            } => {
                let outcome = if *refused { "refused" } else { "checked" };
                AuditRecord {
                    subject: subject.clone(),
                    decision: decision(
                        outcome,
                        refused.then_some("too_many_checks"),
                        Some(method),
                        Some(u64::try_from(*values).unwrap_or(u64::MAX)),
                    ),
                    ..AuditRecord::new(AuditKind::Import, outcome)
                }
            }
            AuditEvent::FilesBackedUp {
                subject,
                backup,
                files,
                ..
            } => AuditRecord {
                request_id: Some(backup.clone()),
                subject: subject.clone(),
                decision: decision(
                    "backed_up",
                    None,
                    Some("files.backup"),
                    Some(u64::try_from(*files).unwrap_or(u64::MAX)),
                ),
                ..AuditRecord::new(AuditKind::FilesBackup, "backed_up")
            },
            AuditEvent::FilesRestored {
                subject,
                backup,
                files,
                ..
            } => AuditRecord {
                request_id: Some(backup.clone()),
                subject: subject.clone(),
                decision: decision(
                    "restored",
                    None,
                    Some("files.restore"),
                    Some(u64::try_from(*files).unwrap_or(u64::MAX)),
                ),
                ..AuditRecord::new(AuditKind::FilesRestore, "restored")
            },
            AuditEvent::RecoveryConfirmed {
                subject, already, ..
            } => AuditRecord {
                subject: subject.clone(),
                decision: decision(
                    "confirmed",
                    already.then_some("already"),
                    Some("recovery.confirm"),
                    None,
                ),
                ..AuditRecord::new(AuditKind::RecoveryConfirm, "confirmed")
            },
            AuditEvent::ProofFailed { pid, kind } => AuditRecord {
                subject: subject(*pid),
                decision: decision("failed", Some("wrong_secret"), None, None),
                ..AuditRecord::new(*kind, "failed")
            },
            AuditEvent::BackedUp { pid, backup, items } => AuditRecord {
                request_id: Some(backup.clone()),
                subject: subject(*pid),
                decision: decision(
                    "backed_up",
                    None,
                    Some("backup.create"),
                    Some(u64::try_from(*items).unwrap_or(u64::MAX)),
                ),
                ..AuditRecord::new(AuditKind::Backup, "backed_up")
            },
            AuditEvent::Recovered {
                subject,
                backup,
                items,
                ..
            } => AuditRecord {
                request_id: Some(backup.clone()),
                subject: subject.clone(),
                decision: decision(
                    "recovered",
                    None,
                    Some("vault.recover"),
                    Some(u64::try_from(*items).unwrap_or(u64::MAX)),
                ),
                ..AuditRecord::new(AuditKind::Recover, "recovered")
            },
        }
    }
}

fn decision(
    outcome: &str,
    reason: Option<&str>,
    method: Option<&str>,
    count: Option<u64>,
) -> DecisionSummary {
    DecisionSummary {
        outcome: outcome.to_owned(),
        reason: reason.map(str::to_owned),
        method: method.map(str::to_owned),
        count,
    }
}

/// Lower-case hex, as the approval statement shows a manifest's hash.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(2 * bytes.len()), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The log as the daemon holds it: the writer while the vault is unlocked,
/// the queue, and when the head was last saved in the vault's header.
///
/// Only a save that succeeded resets the count of entries after the saved
/// head. A save that failed is tried again by the ticks, after
/// [`ANCHOR_RETRY_FIRST`] and then waits that double up to
/// [`ANCHOR_INTERVAL`], and not by events, so a vault that cannot take the
/// write (a read-only one) is not tried on every event. The count is taken
/// from the log when it opens, so a save that failed at lock is made up
/// after the next unlock.
#[derive(Debug, Default)]
pub struct AuditLog {
    writer: Option<AuditWriter>,
    queue: VecDeque<AuditRecord>,
    /// Events the queue had no room for since it was last written.
    dropped: u64,
    /// Entries in the log after the head saved in the vault's header.
    since_anchor: u64,
    /// Awake time when the current wait started: the 15-minute window (the
    /// first tick after a save or an unlock), or the wait after a failed
    /// save; `None` until the next tick.
    window_start: Option<Duration>,
    /// The last save failed: the wait before a tick tries again.
    retry_wait: Option<Duration>,
    /// Opening the log failed and was reported; not repeated until the
    /// next unlock.
    open_failed: bool,
}

impl AuditLog {
    pub fn is_open(&self) -> bool {
        self.writer.is_some()
    }

    /// Opens the writer for the unlocked `v` when it is not open, records
    /// what it found in the log, and writes what the queue holds. Returns
    /// whether it is open.
    pub fn open(&mut self, v: &Vault) -> bool {
        if self.writer.is_some() {
            return true;
        }
        match v.open_audit() {
            Ok((w, report)) => {
                // Entries after the saved head: none, unless the save at
                // the last lock failed or the daemon was killed first.
                let anchored = v.audit_anchor().map_or(0, |a| a.seq);
                self.since_anchor = w.head_record().seq.saturating_sub(anchored);
                self.writer = Some(w);
                self.open_failed = false;
                self.window_start = None;
                self.retry_wait = None;
                for r in findings(&report).into_iter().rev() {
                    self.queue_front(r);
                }
                // What waited while the log was closed is written now; on
                // a failure it keeps waiting.
                let _ = self.flush();
                true
            }
            Err(e) => {
                if !self.open_failed {
                    log_line!(
                        "envcloakd: warning: the audit log could not be opened ({}); requests that \
                         would release values are denied until it can",
                        e.kind().token()
                    );
                    self.open_failed = true;
                }
                false
            }
        }
    }

    /// Closes the writer (the vault locked), wiping its keys. Returns the
    /// head when entries were written since it was last saved, for the
    /// caller to save; the counts start again at the next open.
    pub fn close(&mut self) -> Option<AuditHead> {
        let w = self.writer.take()?;
        self.open_failed = false;
        let unsaved = (self.since_anchor > 0).then(|| w.head_record());
        self.since_anchor = 0;
        self.window_start = None;
        self.retry_wait = None;
        unsaved
    }

    /// The head, while open.
    pub fn head(&self) -> Option<AuditHead> {
        self.writer.as_ref().map(AuditWriter::head_record)
    }

    /// Entries in the log after the head saved in the vault's header.
    pub fn unanchored(&self) -> u64 {
        self.since_anchor
    }

    /// The last try to save the head failed.
    pub fn anchor_failed(&self) -> bool {
        self.retry_wait.is_some()
    }

    /// Events waiting, and events dropped.
    pub fn backlog(&self) -> (u64, u64) {
        (
            u64::try_from(self.queue.len()).unwrap_or(u64::MAX),
            self.dropped,
        )
    }

    fn queue_back(&mut self, r: AuditRecord) {
        if self.queue.len() >= QUEUE_MAX {
            self.dropped = self.dropped.saturating_add(1);
        } else {
            self.queue.push_back(r);
        }
    }

    fn queue_front(&mut self, r: AuditRecord) {
        if self.queue.len() >= QUEUE_MAX {
            self.dropped = self.dropped.saturating_add(1);
        } else {
            self.queue.push_front(r);
        }
    }

    /// Writes the queue, and the count of dropped events.
    fn flush(&mut self) -> Result<(), AuditError> {
        let Some(w) = self.writer.as_mut() else {
            return Ok(());
        };
        while let Some(r) = self.queue.front() {
            w.append(r)?;
            self.queue.pop_front();
            self.since_anchor += 1;
        }
        if self.dropped > 0 {
            let r = AuditRecord {
                decision: decision("dropped", None, None, Some(self.dropped)),
                ..AuditRecord::new(AuditKind::Dropped, "dropped")
            };
            w.append(&r)?;
            self.dropped = 0;
            self.since_anchor += 1;
        }
        Ok(())
    }

    /// Records `r`: written now when the log is open (after whatever is
    /// queued), else queued. Returns whether it was written.
    pub fn record(&mut self, r: AuditRecord) -> bool {
        match self.write_now(&r) {
            Ok(_) => true,
            Err(_) => {
                self.queue_back(r);
                false
            }
        }
    }

    /// Writes `r` now, durably, after whatever is queued. Nothing is
    /// queued on failure: the caller decides.
    ///
    /// # Errors
    /// The log is not open, or the write failed.
    pub fn write_now(&mut self, r: &AuditRecord) -> Result<u64, AuditError> {
        if self.writer.is_none() {
            return Err(std::io::Error::from(std::io::ErrorKind::NotConnected).into());
        }
        self.flush()?;
        let seq = self
            .writer
            .as_mut()
            .map(|w| w.append(r))
            .unwrap_or_else(
                || Err(std::io::Error::from(std::io::ErrorKind::NotConnected).into()),
            )?;
        self.since_anchor += 1;
        Ok(seq)
    }

    /// The head to save now, if a save is due: [`ANCHOR_EVERY`] entries
    /// since the last, or [`ANCHOR_INTERVAL`] awake since the window
    /// started (`awake`, a tick's reading, starts it). After a failed save
    /// only a tick tries again, once its wait is over.
    pub fn anchor_due(&mut self, awake: Option<Duration>) -> Option<AuditHead> {
        if self.since_anchor == 0 {
            return None;
        }
        let head = self.head()?;
        let wait = match self.retry_wait {
            Some(wait) => wait,
            None if self.since_anchor >= ANCHOR_EVERY => return Some(head),
            None => ANCHOR_INTERVAL,
        };
        let now = awake?;
        match self.window_start {
            None => {
                self.window_start = Some(now);
                None
            }
            Some(start) if now.saturating_sub(start) >= wait => Some(head),
            Some(_) => None,
        }
    }

    /// The head [`AuditLog::anchor_due`] gave was saved (`saved`), and the
    /// counts start again; or the save failed, and a tick tries again after
    /// the next wait, from `awake` (from the next tick when `None`).
    /// Returns whether this changes what was last reported: the first
    /// failure, or the first save after failures.
    pub fn anchor_saved(&mut self, saved: bool, awake: Option<Duration>) -> bool {
        let failing = self.retry_wait.is_some();
        if saved {
            self.since_anchor = 0;
            self.window_start = None;
            self.retry_wait = None;
            failing
        } else {
            self.retry_wait = Some(
                self.retry_wait
                    .map_or(ANCHOR_RETRY_FIRST, |w| (w * 2).min(ANCHOR_INTERVAL)),
            );
            self.window_start = awake;
            !failing
        }
    }
}

/// The entries that record what the writer found when it opened the log.
fn findings(r: &OpenReport) -> Vec<AuditRecord> {
    let mut out = Vec::new();
    let log = |outcome: &str, count: Option<u64>| AuditRecord {
        decision: decision(outcome, None, None, count),
        ..AuditRecord::new(AuditKind::Log, outcome)
    };
    if r.torn_tail_removed {
        out.push(log("torn_tail_removed", Some(r.torn_bytes)));
    }
    if r.damaged {
        out.push(log("damaged", None));
    }
    if let Some((_, anchor)) = r.behind_anchor {
        out.push(log("behind_anchor", Some(anchor)));
    }
    if r.other_vault_moved {
        out.push(log("other_vault_log_moved", None));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_lower_case_hex() {
        assert_eq!(hex(&[0x00, 0xab, 0x7f, 0xff]), "00ab7fff");
        assert_eq!(hex(&[0u8; 32]).len(), 64);
    }

    #[test]
    fn the_queue_is_bounded_and_counts_what_it_drops() {
        let mut log = AuditLog::default();
        for _ in 0..QUEUE_MAX + 5 {
            assert!(!log.record(AuditRecord::new(AuditKind::Lock, "locked")));
        }
        assert_eq!(log.backlog(), (QUEUE_MAX as u64, 5));
        assert!(
            log.write_now(&AuditRecord::new(AuditKind::Lock, "locked"))
                .is_err()
        );
        assert_eq!(log.close(), None);
    }

    #[test]
    fn every_event_has_an_entry_and_lines_carry_no_free_text() {
        let events = [
            AuditEvent::RoleDenied {
                method: "app.reveal",
                pid: 7,
                uid: 501,
            },
            AuditEvent::ForeignPeer { pid: 8, uid: 502 },
            AuditEvent::UnlockFailed { pid: 9 },
            AuditEvent::Unlocked {
                pid: 9,
                created: true,
            },
            AuditEvent::Locked {
                reason: LockReason::Idle,
            },
            AuditEvent::Request(Box::new(RequestAudit {
                pid: 10,
                decision: "covered",
                request_id: None,
                grant_id: Some("01K0000000000000000000000Z".into()),
                reason: None,
                subject: SubjectSummary::default(),
                project: None,
                items: Vec::new(),
                argv: vec!["a command line argument".into()],
            })),
            AuditEvent::Revoked { pid: 11, count: 2 },
        ];
        for e in &events {
            let r = e.record();
            assert!(!r.decision.outcome.is_empty(), "{e:?}");
            if let Some(line) = e.line() {
                assert!(!line.contains("a command line argument"), "{line}");
            }
        }
        assert_eq!(
            events[5].line().unwrap(),
            "envcloakd: audit: request decision=covered id=01K0000000000000000000000Z pid=10"
        );
        assert_eq!(events[5].record().argv_redacted.len(), 1);
    }
}
