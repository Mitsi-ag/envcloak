//! What one audit entry says, and its encoding (layout in docs/VAULT.md
//! "Audit log").
//!
//! An entry is metadata only: who asked (pid, kind, agent, root), for
//! which project and items, what was decided, and the command line with
//! every value masked. The daemon masks the command line before it builds
//! the record (the request's values with the redactor, then the registry's
//! key patterns); this module only bounds it. Every string is capped, so
//! an entry stays well under [`MAX_ENTRY`]: an argument longer than
//! [`MAX_TEXT`] bytes is cut, and arguments past [`MAX_ARGV_BYTES`] in all
//! are dropped, each with a marker saying how much.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::vault::codec::{Dec, Enc};
use crate::vault::{ItemId, Slug, VaultError, VaultErrorKind};

/// The largest encoded entry. The caps below keep every entry under it.
pub const MAX_ENTRY: usize = 64 * 1024;
/// The largest string an entry keeps whole: a path, a label, one argument.
pub const MAX_TEXT: usize = 4096;
/// The command line's bytes an entry keeps in all.
pub const MAX_ARGV_BYTES: usize = 16 * 1024;
/// Arguments an entry keeps.
pub const MAX_ARGS: usize = 256;
/// Items an entry names.
pub const MAX_ITEMS: usize = 256;
/// Named counts an entry keeps ([`DecisionSummary::counts`]).
pub const MAX_COUNTS: usize = 16;

/// The version of a record without named counts: every record an M1
/// build wrote, and every record since that has none, byte for byte.
const RECORD_VERSION: u8 = 1;
/// The version of a record with named counts: version 1's fields, then
/// the counts.
const RECORD_VERSION_COUNTS: u8 = 2;

/// What an entry records. The numbers are part of the log's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuditKind {
    /// A run's request was decided: covered by a grant (a delivery),
    /// pending an approval, or denied.
    Run = 1,
    /// A pending request was approved into a grant, or the proof failed.
    Approve = 2,
    /// A pending request was denied.
    Deny = 3,
    /// Grants were revoked.
    Revoke = 4,
    /// A covered request came with a manifest whose hash changed since the
    /// approval; its bindings were still covered.
    ManifestChanged = 5,
    /// A client-role peer called an `app`-role method.
    RoleDenied = 6,
    /// A peer running as another uid connected and was closed.
    ForeignPeer = 7,
    /// The vault was created or unlocked, or an unlock failed.
    Unlock = 8,
    /// The vault locked.
    Lock = 9,
    /// A proof was refused because of who the caller is.
    ProofRefused = 10,
    /// Events were lost while the log could not be written: the queue that
    /// holds them meanwhile was full. The count says how many.
    Dropped = 11,
    /// What the writer found when it opened the log: a torn last entry it
    /// removed, damage, or a log that ends before the vault's saved head.
    Log = 12,
    /// An item was added (`envcloak add`). Adding needs no proof.
    Add = 13,
    /// An item's value was replaced (`envcloak rotate`), with a proof, or
    /// the proof failed.
    Rotate = 14,
    /// An item was removed (`envcloak rm`), with a proof, or the proof
    /// failed. The count says how many grants that ended.
    Remove = 15,
    /// Env-file values were imported (`envcloak init --import`, `envcloak
    /// import`): the items made; the count says how many items were
    /// reused. Importing needs no proof.
    Import = 16,
    /// An encrypted backup of files about to be deleted was written. The
    /// request id is the backup's; the count says how many files.
    FilesBackup = 17,
    /// A file backup was handed back for `envcloak init --undo`, with a
    /// proof, or the proof failed.
    FilesRestore = 18,
    /// The Recovery Kit was confirmed, with the kit as the proof, or the
    /// proof failed.
    RecoveryConfirm = 19,
    /// An encrypted backup of the vault was written (`envcloak backup
    /// create`). The request id is the backup's; the count says how many
    /// items it holds.
    Backup = 20,
    /// The vault was restored from an encrypted backup (`envcloak
    /// recover`), with the Recovery Kit as the proof, or the proof failed.
    /// The request id is the backup's; the count says how many items the
    /// restored vault holds.
    Recover = 21,
    // M2 and M2b: each kind joins `ALL`, which `verify` reads, with the task
    // that writes it (docs/VAULT.md "Reserved for M2 and M2b").
    /// Candidate tokens were compared with the vault by keyed hash
    /// (`scan.match`, for import, doctor or scrub), or the call was refused
    /// for a spent budget. The reason is the purpose; the count says how
    /// many were compared, and the named counts how many of each kind
    /// (never a candidate).
    ScanMatch = 23,
    /// Items were marked "exposed: rotate" (`items.mark_exposed`): the items
    /// marked; the count says how many.
    MarkExposed = 24,
    /// A file backup v2 committed, with its creator and purpose. The request id
    /// is the backup's; the count says how many files.
    BackupV2 = 25,
    /// A restore lease opened on a file backup v2, with a proof, before its
    /// first chunk is read; or the proof failed. The request id is the
    /// backup's; the count says how many files.
    RestoreV2 = 26,
    /// An item's classification was set by hand (`items.reclassify`): the
    /// item; the reason names the change (`test_to_live`), and the count
    /// how many grants that bound it ended. Towards `test` or `unknown`
    /// with a proof, or the proof failed.
    Reclassify = 30,
    /// An approval was refused by the live-key guard (`live_not_ticked`):
    /// the request id, and the items whose live bindings it left unticked.
    LiveRefused = 31,
}

impl AuditKind {
    /// Every kind, in number order.
    pub const ALL: [AuditKind; 27] = [
        AuditKind::Run,
        AuditKind::Approve,
        AuditKind::Deny,
        AuditKind::Revoke,
        AuditKind::ManifestChanged,
        AuditKind::RoleDenied,
        AuditKind::ForeignPeer,
        AuditKind::Unlock,
        AuditKind::Lock,
        AuditKind::ProofRefused,
        AuditKind::Dropped,
        AuditKind::Log,
        AuditKind::Add,
        AuditKind::Rotate,
        AuditKind::Remove,
        AuditKind::Import,
        AuditKind::FilesBackup,
        AuditKind::FilesRestore,
        AuditKind::RecoveryConfirm,
        AuditKind::Backup,
        AuditKind::Recover,
        AuditKind::ScanMatch,
        AuditKind::MarkExposed,
        AuditKind::BackupV2,
        AuditKind::RestoreV2,
        AuditKind::Reclassify,
        AuditKind::LiveRefused,
    ];

    /// The kind's stable token.
    pub const fn token(self) -> &'static str {
        match self {
            AuditKind::Run => "run",
            AuditKind::Approve => "approve",
            AuditKind::Deny => "deny",
            AuditKind::Revoke => "revoke",
            AuditKind::ManifestChanged => "manifest_changed",
            AuditKind::RoleDenied => "role_denied",
            AuditKind::ForeignPeer => "foreign_peer",
            AuditKind::Unlock => "unlock",
            AuditKind::Lock => "lock",
            AuditKind::ProofRefused => "proof_refused",
            AuditKind::Dropped => "dropped",
            AuditKind::Log => "log",
            AuditKind::Add => "add",
            AuditKind::Rotate => "rotate",
            AuditKind::Remove => "remove",
            AuditKind::Import => "import",
            AuditKind::FilesBackup => "files_backup",
            AuditKind::FilesRestore => "files_restore",
            AuditKind::RecoveryConfirm => "recovery_confirm",
            AuditKind::Backup => "backup",
            AuditKind::Recover => "recover",
            AuditKind::ScanMatch => "scan_match",
            AuditKind::MarkExposed => "mark_exposed",
            AuditKind::BackupV2 => "backup_v2",
            AuditKind::RestoreV2 => "restore_v2",
            AuditKind::Reclassify => "reclassify",
            AuditKind::LiveRefused => "live_refused",
        }
    }

    fn from_u8(v: u8) -> Option<AuditKind> {
        AuditKind::ALL.into_iter().find(|k| *k as u8 == v)
    }
}

/// Who made the request, as the daemon read it from the kernel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubjectSummary {
    /// The calling process.
    pub pid: i32,
    /// The caller's uid, recorded only when it is not this user's.
    pub uid: Option<u32>,
    /// `terminal`, `agent` or `unknown`, when the caller's evidence was
    /// read.
    pub kind: Option<String>,
    /// The agent's display name, when one is involved.
    pub agent: Option<String>,
    /// The process a grant is rooted at.
    pub root_pid: Option<i32>,
    /// The root's executable path.
    pub root_exe: Option<String>,
}

/// The project a request came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSummary {
    /// Its canonical directory.
    pub dir: String,
    /// SHA-256 of the manifest's bytes as the daemon read them.
    pub manifest_sha256: [u8; 32],
    /// SHA-256 of the manifest at approval, when it differs.
    pub approved_sha256: Option<[u8; 32]>,
}

/// What was decided. Every string is a fixed token of the daemon's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionSummary {
    /// `covered`, `pending`, `denied`, `approved`, `failed`, `refused`,
    /// `revoked`, `unlocked`, `created`, `locked`, ...
    pub outcome: String,
    /// Why, when there is a reason.
    pub reason: Option<String>,
    /// The method called, for events about a call.
    pub method: Option<String>,
    /// A count, for events that have one.
    pub count: Option<u64>,
    /// Named counts, for events that have several (`scan.match`'s): each a
    /// fixed token of the daemon's and a number, at most [`MAX_COUNTS`].
    /// A record with none is written as version 1, as before they existed.
    pub counts: Vec<(String, u64)>,
}

/// One audit entry. Metadata only; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// When it happened, to the millisecond.
    pub at: SystemTime,
    pub kind: AuditKind,
    /// The pending request's id (8 Crockford base32 characters), or for
    /// [`AuditKind::FilesBackup`], [`AuditKind::FilesRestore`],
    /// [`AuditKind::BackupV2`] and [`AuditKind::RestoreV2`] the file
    /// backup's (26).
    pub request_id: Option<String>,
    /// The grant's id (26 Crockford base32 characters).
    pub grant_id: Option<String>,
    pub subject: SubjectSummary,
    pub project: Option<ProjectSummary>,
    /// The items the request bound, by id and slug.
    pub items: Vec<(ItemId, Slug)>,
    pub decision: DecisionSummary,
    /// The command line, with every value masked by the daemon.
    pub argv_redacted: Vec<String>,
}

impl AuditRecord {
    /// A record of `kind` with `outcome`, made now, with nothing else set.
    pub fn new(kind: AuditKind, outcome: &str) -> Self {
        AuditRecord {
            at: SystemTime::now(),
            kind,
            request_id: None,
            grant_id: None,
            subject: SubjectSummary::default(),
            project: None,
            items: Vec::new(),
            decision: DecisionSummary {
                outcome: outcome.to_owned(),
                ..DecisionSummary::default()
            },
            argv_redacted: Vec::new(),
        }
    }

    /// The encoding sealed into an entry, with every string capped.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let at_ms = self
            .at
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let mut e = Enc::new();
        let counts = &self.decision.counts[..self.decision.counts.len().min(MAX_COUNTS)];
        let version = if counts.is_empty() {
            RECORD_VERSION
        } else {
            RECORD_VERSION_COUNTS
        };
        e.u8(version).u64(at_ms).u8(self.kind as u8);
        opt_text(&mut e, self.request_id.as_deref());
        opt_text(&mut e, self.grant_id.as_deref());
        let s = &self.subject;
        e.raw(&s.pid.to_be_bytes());
        match s.uid {
            None => e.u8(0),
            Some(uid) => e.u8(1).raw(&uid.to_be_bytes()),
        };
        opt_text(&mut e, s.kind.as_deref());
        opt_text(&mut e, s.agent.as_deref());
        match s.root_pid {
            None => e.u8(0),
            Some(pid) => e.u8(1).raw(&pid.to_be_bytes()),
        };
        opt_text(&mut e, s.root_exe.as_deref());
        match &self.project {
            None => {
                e.u8(0);
            }
            Some(p) => {
                e.u8(1).str(&capped(&p.dir)).raw(&p.manifest_sha256);
                match &p.approved_sha256 {
                    None => e.u8(0),
                    Some(h) => e.u8(1).raw(h),
                };
            }
        }
        let items = &self.items[..self.items.len().min(MAX_ITEMS)];
        e.raw(&u32::try_from(items.len()).unwrap_or(0).to_be_bytes());
        for (id, slug) in items {
            e.raw(id.as_bytes()).str(slug.as_str());
        }
        let d = &self.decision;
        e.str(&capped(&d.outcome));
        opt_text(&mut e, d.reason.as_deref());
        opt_text(&mut e, d.method.as_deref());
        e.opt_u64(d.count);
        e.strs(&capped_argv(&self.argv_redacted));
        if !counts.is_empty() {
            e.raw(&u32::try_from(counts.len()).unwrap_or(0).to_be_bytes());
            for (name, n) in counts {
                e.str(&capped(name)).u64(*n);
            }
        }
        e.finish()
    }

    /// Decodes [`AuditRecord::encode`]'s output. The entry was
    /// authenticated before this runs, so a failure means a bug or a newer
    /// format, never an attacker's bytes.
    pub(crate) fn decode(b: &[u8]) -> Result<Self, VaultError> {
        let corrupt = || VaultError::from(VaultErrorKind::Corrupt);
        let mut d = Dec::new(b);
        let version = d.u8()?;
        if version != RECORD_VERSION && version != RECORD_VERSION_COUNTS {
            return Err(corrupt());
        }
        let at = UNIX_EPOCH + Duration::from_millis(d.u64()?);
        let kind = AuditKind::from_u8(d.u8()?).ok_or_else(corrupt)?;
        let request_id = d.opt_string()?;
        let grant_id = d.opt_string()?;
        let pid = i32::from_be_bytes(d.array()?);
        let uid = if d.bool()? {
            Some(u32::from_be_bytes(d.array()?))
        } else {
            None
        };
        let subject_kind = d.opt_string()?;
        let agent = d.opt_string()?;
        let root_pid = if d.bool()? {
            Some(i32::from_be_bytes(d.array()?))
        } else {
            None
        };
        let root_exe = d.opt_string()?;
        let project = if d.bool()? {
            let dir = d.string()?;
            let manifest_sha256 = d.array()?;
            let approved_sha256 = if d.bool()? { Some(d.array()?) } else { None };
            Some(ProjectSummary {
                dir,
                manifest_sha256,
                approved_sha256,
            })
        } else {
            None
        };
        let n = d.u32()?;
        if usize::try_from(n).map_err(|_| corrupt())? > MAX_ITEMS {
            return Err(corrupt());
        }
        let mut items = Vec::new();
        for _ in 0..n {
            let id = ItemId::from_bytes(d.array()?);
            let slug = Slug::new(&d.string()?).map_err(|_| corrupt())?;
            items.push((id, slug));
        }
        let outcome = d.string()?;
        let reason = d.opt_string()?;
        let method = d.opt_string()?;
        let count = d.opt_u64()?;
        let argv_redacted = d.strings()?;
        let mut counts = Vec::new();
        if version == RECORD_VERSION_COUNTS {
            let n = d.u32()?;
            // Written only with one count or more, and never more than the cap.
            if n == 0 || usize::try_from(n).map_err(|_| corrupt())? > MAX_COUNTS {
                return Err(corrupt());
            }
            for _ in 0..n {
                let name = d.string()?;
                counts.push((name, d.u64()?));
            }
        }
        d.end()?;
        Ok(AuditRecord {
            at,
            kind,
            request_id,
            grant_id,
            subject: SubjectSummary {
                pid,
                uid,
                kind: subject_kind,
                agent,
                root_pid,
                root_exe,
            },
            project,
            items,
            decision: DecisionSummary {
                outcome,
                reason,
                method,
                count,
                counts,
            },
            argv_redacted,
        })
    }
}

fn opt_text(e: &mut Enc, s: Option<&str>) {
    match s {
        None => e.u8(0),
        Some(s) => e.u8(1).str(&capped(s)),
    };
}

/// `s`, cut to [`MAX_TEXT`] bytes at a character boundary with a marker
/// saying how many bytes went.
fn capped(s: &str) -> std::borrow::Cow<'_, str> {
    if s.len() <= MAX_TEXT {
        return s.into();
    }
    let mut end = MAX_TEXT;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}[envcloak: {} bytes cut]", &s[..end], s.len() - end).into()
}

/// The command line an entry keeps: each argument capped, at most
/// [`MAX_ARGS`] of them and [`MAX_ARGV_BYTES`] in all, and a marker for
/// what was dropped.
fn capped_argv(argv: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut total = 0usize;
    for (i, a) in argv.iter().enumerate() {
        let a = capped(a);
        if out.len() == MAX_ARGS || total + a.len() > MAX_ARGV_BYTES {
            out.push(format!("[envcloak: {} more arguments cut]", argv.len() - i));
            break;
        }
        total += a.len();
        out.push(a.into_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> AuditRecord {
        AuditRecord {
            at: UNIX_EPOCH + Duration::from_millis(1_790_000_000_123),
            kind: AuditKind::Run,
            request_id: Some("ABCDEFGH".into()),
            grant_id: Some("01K0000000000000000000000Z".into()),
            subject: SubjectSummary {
                pid: 4242,
                uid: Some(501),
                kind: Some("agent".into()),
                agent: Some("Claude Code".into()),
                root_pid: Some(4000),
                root_exe: Some("/usr/local/bin/claude".into()),
            },
            project: Some(ProjectSummary {
                dir: "/src/acme-web".into(),
                manifest_sha256: [7; 32],
                approved_sha256: Some([8; 32]),
            }),
            items: vec![(ItemId::generate(), Slug::new("openai/acme-web").unwrap())],
            decision: DecisionSummary {
                outcome: "covered".into(),
                reason: Some("because".into()),
                method: Some("run.request".into()),
                count: Some(3),
                counts: Vec::new(),
            },
            argv_redacted: vec!["./emit".into(), String::new(), "\u{e9}".into()],
        }
    }

    #[test]
    fn records_round_trip() {
        let r = full();
        assert_eq!(AuditRecord::decode(&r.encode()).unwrap(), r);
        let bare = AuditRecord {
            at: UNIX_EPOCH,
            ..AuditRecord::new(AuditKind::Lock, "locked")
        };
        assert_eq!(AuditRecord::decode(&bare.encode()).unwrap(), bare);
        for k in AuditKind::ALL {
            assert_eq!(AuditKind::from_u8(k as u8), Some(k));
        }
        assert_eq!(AuditKind::from_u8(0), None);
        // Kind 22 and kinds from 27 on are reserved for later tasks, not
        // written by this build.
        for n in [22, 27, 46] {
            assert_eq!(AuditKind::from_u8(n), None, "{n}");
        }
        // Numbers in order, each token its own.
        for (i, k) in AuditKind::ALL.iter().enumerate() {
            assert!(i == 0 || (AuditKind::ALL[i - 1] as u8) < (*k as u8));
            assert_eq!(
                AuditKind::ALL
                    .iter()
                    .filter(|o| o.token() == k.token())
                    .count(),
                1
            );
        }
        // The backup v2 kinds are read back: `verify` takes their entries.
        assert_eq!(AuditKind::from_u8(25), Some(AuditKind::BackupV2));
        assert_eq!(AuditKind::from_u8(26), Some(AuditKind::RestoreV2));
        // And M2-11's.
        assert_eq!(AuditKind::from_u8(23), Some(AuditKind::ScanMatch));
        assert_eq!(AuditKind::from_u8(24), Some(AuditKind::MarkExposed));
    }

    /// A record's named counts (M2-11: `scan.match`'s counts by kind) come
    /// back as written, in order. A record without any is written exactly
    /// as before they existed (version 1, the bytes an M1 build wrote), so
    /// every entry an earlier build wrote still reads, and a record with
    /// some is version 2. More than [`MAX_COUNTS`] are cut to it, and each
    /// name is capped like any string.
    ///
    /// Mutations: counts dropped on decode (the round trip fails); version
    /// 2 for every record (the version 1 bytes change).
    #[test]
    fn named_counts_round_trip_and_leave_other_records_as_they_were() {
        let plain = full();
        let bytes = plain.encode();
        assert_eq!(bytes[0], 1);
        let mut counted = plain.clone();
        counted.decision.counts = vec![
            ("candidates".into(), 4096),
            ("compared".into(), 0),
            ("skipped_guessable".into(), u64::MAX),
        ];
        let with = counted.encode();
        assert_eq!(with[0], 2);
        assert_eq!(AuditRecord::decode(&with).unwrap(), counted);
        // The same record without its counts is the version 1 record, byte
        // for byte, but for the version and the counts at the end.
        assert_eq!(with[1..bytes.len()], bytes[1..]);
        let mut many = plain.clone();
        many.decision.counts = (0..40).map(|i| (format!("count_{i}"), i)).collect();
        many.decision.counts[0].0 = "\u{20ac}".repeat(4000);
        let back = AuditRecord::decode(&many.encode()).unwrap();
        assert_eq!(back.decision.counts.len(), MAX_COUNTS);
        assert!(back.decision.counts[0].0.ends_with("bytes cut]"));
        assert_eq!(back.decision.counts[1], ("count_1".to_owned(), 1));
        assert_eq!(
            back.decision.counts[MAX_COUNTS - 1].1,
            (MAX_COUNTS - 1) as u64
        );
    }

    /// 100 KB of command line (gate 31's size) and long strings everywhere
    /// still give an entry under the cap, cut at character boundaries.
    #[test]
    fn every_string_is_capped() {
        let mut r = full();
        let long = "\u{20ac}".repeat(40_000);
        r.argv_redacted = vec![long.clone(); 30];
        r.argv_redacted.extend((0..1000).map(|i| i.to_string()));
        r.subject.root_exe = Some(long.clone());
        r.subject.agent = Some(long.clone());
        r.project.as_mut().unwrap().dir.clone_from(&long);
        r.decision.reason = Some(long);
        let encoded = r.encode();
        assert!(encoded.len() < MAX_ENTRY, "{}", encoded.len());
        let back = AuditRecord::decode(&encoded).unwrap();
        assert!(back.argv_redacted.len() <= MAX_ARGS + 1);
        assert!(back.argv_redacted[0].ends_with("bytes cut]"));
        assert!(back.argv_redacted[0].len() < MAX_TEXT + 40);
        assert!(
            back.argv_redacted
                .last()
                .unwrap()
                .ends_with("more arguments cut]")
        );
        let kept: usize = back.argv_redacted.iter().map(String::len).sum();
        assert!(kept < MAX_ARGV_BYTES + MAX_TEXT + 80);
    }

    #[test]
    fn short_or_unknown_input_is_corrupt() {
        let bytes = full().encode();
        for cut in [0, 1, 9, bytes.len() - 1] {
            assert!(AuditRecord::decode(&bytes[..cut]).is_err(), "{cut}");
        }
        let mut other = bytes.clone();
        other[0] = 3;
        assert!(AuditRecord::decode(&other).is_err());
        // Version 2 says counts follow: a version 1 body under it is cut
        // short, and a count list that is empty, or longer than the cap, is
        // never written.
        let mut two = bytes.clone();
        two[0] = 2;
        assert!(AuditRecord::decode(&two).is_err());
        for n in [0u32, u32::try_from(MAX_COUNTS).unwrap() + 1] {
            let mut listed = two.clone();
            listed.extend_from_slice(&n.to_be_bytes());
            assert!(AuditRecord::decode(&listed).is_err(), "{n}");
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(AuditRecord::decode(&trailing).is_err());
    }
}
