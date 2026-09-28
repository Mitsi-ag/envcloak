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

const RECORD_VERSION: u8 = 1;

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
}

impl AuditKind {
    /// Every kind, in number order.
    pub const ALL: [AuditKind; 15] = [
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
}

/// One audit entry. Metadata only; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// When it happened, to the millisecond.
    pub at: SystemTime,
    pub kind: AuditKind,
    /// The pending request's id (8 Crockford base32 characters).
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
        e.u8(RECORD_VERSION).u64(at_ms).u8(self.kind as u8);
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
        e.finish()
    }

    /// Decodes [`AuditRecord::encode`]'s output. The entry was
    /// authenticated before this runs, so a failure means a bug or a newer
    /// format, never an attacker's bytes.
    pub(crate) fn decode(b: &[u8]) -> Result<Self, VaultError> {
        let corrupt = || VaultError::from(VaultErrorKind::Corrupt);
        let mut d = Dec::new(b);
        if d.u8()? != RECORD_VERSION {
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
        assert_eq!(AuditKind::from_u8(16), None);
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
        other[0] = 2;
        assert!(AuditRecord::decode(&other).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(AuditRecord::decode(&trailing).is_err());
    }
}
