//! File backups v2 over the socket (SPEC §6.4 "Backups", M2 plan D-07;
//! docs/IPC.md "Backups v2"): `backup.v2.begin`, `put`, `commit`,
//! `record_result`, `open_restore`, `read` and `list`. The format is
//! `envcloak_core::file_backup_v2`.
//!
//! **Upload.** Any client may back up files under the allowed roots
//! ([`allowed_path`]): a scrub an agent runs must back up first. So the
//! daemon, never the client, says who made a backup: `begin` reads the
//! caller's evidence from the kernel and seals the subject's kind, a digest
//! of its evidence, the agent's label, the caller's process instance (pid,
//! start time and, on macOS, the audit token's pid version) with the boot
//! it runs in, and the creator's chain as the restore's session and
//! terminal check reads it. Only that instance may `put`, `commit` and
//! `record_result`, and only while it runs: another process, one in the
//! same agent root that knows or lists the id included, gets
//! `not_backup_owner`, changes nothing and learns nothing more, and so
//! does a call on the creator's connection after the creator exited,
//! reaped or not. The daemon watches the creator for its exit through an
//! [`envcloak_sys::ProcessWatch`] (a pidfd on Linux) taken at `begin` and
//! kept while the backup is in progress or awaits a result; without one
//! (after a restart, or past [`MAX_CREATOR_WATCHES`]) it reads the
//! process table, where a process that exited and is not yet reaped does
//! not run either. A
//! committed backup's contents are frozen (`backup_frozen`), and each
//! file's result is recorded once. A backup in progress is dropped (its
//! staging directory removed) when its creator exits, after
//! [`UPLOAD_IDLE`] without a call, at lock and at a restart; it is never
//! listed. One root holds at most [`MAX_UPLOADS_PER_ROOT`] of them.
//!
//! **Restore.** `open_restore` takes one passphrase proof from a terminal
//! subject, after the caller's evidence was read and before the
//! passphrase is looked at, refuses a backup an agent or an unknown
//! process made unless `created_by_agent_ticked`, one whose results are
//! not all recorded unless `unrecorded`, and a caller that shares a
//! session or a terminal with a process of the creator's sealed chain
//! that still runs (`requester_terminal`, as for approvals), whether or
//! not this daemon took the backup. Argon2id runs once. The whole backup
//! is then opened and checked (every chunk, every file's SHA-256), so no
//! restore is ever partial; the audit entry is written durably; and only
//! then is a lease issued, bound to the backup, the caller's process
//! instance and its terminal. `read` hands out one chunk under the lease,
//! on fresh connections, only to that process on that terminal, and only
//! if the lease still stands once the chunk is read: that process still
//! runs, is still on that terminal and the lease is not past its idle
//! limit. A lease ends when its process exits (reaped or not), after 60
//! seconds idle, at lock and at a restart; an audit entry that cannot be
//! written issues no lease, so no chunk.
//!
//! **Locks.** A lock while a call is in flight stops it: a `read`
//! delivers nothing, a `put` or `commit` reports the backup ended, an
//! `open_restore` issues no lease, a `record_result` records nothing and
//! a `list` stops before the next backup it would open; a backup and a
//! result are put in place only under the state lock. Backups are opened
//! (their metadata read and opened) outside the state lock.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use envcloak_core::audit::{AuditKind, SubjectSummary};
use envcloak_core::file_backup::FileBackupId;
use envcloak_core::file_backup_v2::{
    BackupCreator, BackupOwner, BackupPurpose, CHUNK_V2, CreatorKind, CreatorProcess,
    FileBackupV2Reader, FileBackupV2Writer, FileBackupsV2, MAX_CHAIN_V2, MAX_LABEL_V2, PlannedFile,
    check_plan, chunks_of, list_file_backups_v2, purge_file_backups_v2,
};
use envcloak_core::vault::{VaultError, VaultErrorKind};
use envcloak_ipc::proto::{
    BackupBeginParams, BackupChunk, BackupIdParams, BackupPutParams, BackupReadParams,
    BackupResultParams, ErrorKind, NoParams, OpenRestoreParams,
};
use envcloak_ipc::view::{
    BackupBegunView, BackupCommittedView, BackupCreatorView, BackupEntryView, BackupListView,
    BackupPutView, BackupResultView, BackupStateView, RestoreFileView, RestoreLeaseView,
    RestoreStatementView,
};
use envcloak_ipc::{RpcError, WireSecret};
use envcloak_policy::{
    Ancestor, EvidenceError, ProcessInstance, ProofRefusal, SubjectEvidence, SubjectKind,
};
use envcloak_sys::{PeerIdentity, ProcessWatch, StartTime};
use sha2::{Digest, Sha256};

use crate::audit::AuditEvent;
use crate::clock::Clocks;
use crate::import::prove_as;
use crate::lock::Reading;
use crate::requests::{evidence, refuse_unless_prover, subject_summary};
use crate::server::{Shared, locked, refuse_if_traced};
use crate::state::{State, vault_reason};

/// How long a restore lease may sit unused.
pub const LEASE_IDLE: Duration = Duration::from_secs(60);
/// Backups in progress at once.
pub const MAX_UPLOADS: usize = 16;
/// Backups in progress at once for the processes of one root (an agent
/// and its commands, or one terminal session), so one root cannot hold
/// every slot.
pub const MAX_UPLOADS_PER_ROOT: usize = 4;
/// How long a backup in progress may go without a call before it is
/// dropped.
pub const UPLOAD_IDLE: Duration = Duration::from_secs(120);
/// Restore leases open at once.
pub const MAX_LEASES: usize = 16;
/// Creators of committed backups awaiting a result that the daemon keeps
/// watching ([`ProcessWatch`], a descriptor each on Linux). Past it, a
/// creator is looked up in the process table instead, which answers the
/// same.
pub const MAX_CREATOR_WATCHES: usize = 64;
/// Backups `backup.v2.list` names, newest first.
pub const MAX_LISTED: usize = 512;
// Every process of a creator's chain the daemon reads is sealed.
const _: () = assert!(MAX_CHAIN_V2 >= envcloak_sys::MAX_ANCESTRY);
/// The bytes of file entries a restore statement carries at most.
const STATEMENT_BUDGET: usize = 512 * 1024;

/// The directories under the home that hold agent configs and
/// transcripts (M2 plan Map C §4 and §6), and the files there.
const HOME_DIRS: [&str; 13] = [
    ".claude",
    ".codex",
    ".cursor",
    ".gemini",
    ".copilot",
    ".kimi",
    ".kimi-code",
    ".qwen",
    ".agents",
    ".config/opencode",
    ".local/share/opencode",
    ".config/goose",
    ".local/share/goose",
];
const HOME_FILES: [&str; 2] = [".claude.json", ".aider.conf.yml"];
/// Agent files a project may hold, by name.
const PROJECT_FILES: [&str; 8] = [
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".mcp.json",
    ".goosehints",
    ".aider.chat.history.md",
    ".aider.input.history",
    ".aider.conf.yml",
];
/// Agent directories a project may hold: any file below one.
const PROJECT_DIRS: [&str; 6] = [".claude", ".codex", ".cursor", ".gemini", ".kimi", ".qwen"];

/// Whether `path` is a file a backup v2 may hold (docs/IPC.md "Backups
/// v2"): an absolute path of 1 to 4096 bytes without a NUL, an empty, `.`
/// or `..` component or a trailing `/`, that is an env file (`.env`,
/// `.env.<suffix>`), is under `<data>/mcp/`, is under one of the agent
/// roots of the home or is one of its agent files, or is a project's
/// agent file or under a project's agent directory. The test is on the
/// path as written: a restore writes it back without following a
/// symlink.
pub fn allowed_path(path: &str, home: Option<&Path>, data_dir: &Path) -> bool {
    if path.is_empty() || path.len() > 4096 || path.contains('\0') || !path.starts_with('/') {
        return false;
    }
    let parts: Vec<&str> = path[1..].split('/').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return false;
    }
    let Some(name) = parts.last() else {
        return false;
    };
    if *name == ".env" || name.strip_prefix(".env.").is_some_and(|s| !s.is_empty()) {
        return true;
    }
    let p = Path::new(path);
    let under = |root: &Path, sub: &str| {
        let canonical = std::fs::canonicalize(root).ok();
        [Some(root.to_path_buf()), canonical]
            .into_iter()
            .flatten()
            .any(|r| p.starts_with(r.join(sub)) && p != r.join(sub))
    };
    let is = |root: &Path, sub: &str| {
        let canonical = std::fs::canonicalize(root).ok();
        [Some(root.to_path_buf()), canonical]
            .into_iter()
            .flatten()
            .any(|r| p == r.join(sub))
    };
    if under(data_dir, "mcp") {
        return true;
    }
    if let Some(home) = home {
        if HOME_DIRS.iter().any(|d| under(home, d)) || HOME_FILES.iter().any(|f| is(home, f)) {
            return true;
        }
    }
    if PROJECT_FILES.contains(name) {
        return true;
    }
    let dirs = &parts[..parts.len() - 1];
    if dirs.iter().any(|d| PROJECT_DIRS.contains(d)) {
        return true;
    }
    *name == "mcp.json" && dirs.last() == Some(&".vscode")
}

/// The running boot's id (`envcloak_sys::boot_id`), read once: `None` on
/// macOS, and on Linux when it cannot be read, which no recorded boot
/// matches.
fn this_boot() -> Option<[u8; 16]> {
    static BOOT: OnceLock<Option<[u8; 16]>> = OnceLock::new();
    *BOOT.get_or_init(|| envcloak_sys::boot_id().ok().flatten())
}

/// Whether processes recorded in boot `boot` are of this boot: the same
/// id, and on Linux an id at all.
fn this_boots(boot: Option<[u8; 16]>) -> bool {
    boot == this_boot()
        && (boot.is_some() || !cfg!(any(target_os = "linux", target_os = "android")))
}

/// The process instance the kernel identified `peer` as, in this boot.
fn owner_of(peer: &PeerIdentity) -> BackupOwner {
    BackupOwner {
        pid: peer.pid,
        start_time: peer.start_time.raw(),
        token: peer.pidversion,
        boot: this_boot(),
    }
}

/// Whether `peer` is the process instance `owner`: the same pid and start
/// time in the same boot, and the same pid version when both know one.
/// Another process in the same tree, root or session is not, nor a process
/// of a later boot with the same pid and start time.
fn same_instance(owner: &BackupOwner, peer: &PeerIdentity) -> bool {
    this_boots(owner.boot)
        && owner.pid == peer.pid
        && owner.start_time == peer.start_time.raw()
        && match (owner.token, peer.pidversion) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        }
}

/// Whether process instance `i` still runs: a process that exited and is
/// not yet reaped (a zombie) keeps its pid and start time but does not.
fn running(i: &ProcessInstance) -> bool {
    envcloak_sys::process_running(i.pid, i.start_time)
}

/// Whether `owner` still runs: in this boot, and running, as `watch` says
/// when the daemon holds one for it (taken from the same process
/// instance), or as the process table says. A process that exited and is
/// not yet reaped does not run.
fn owner_alive(owner: &BackupOwner, watch: Option<&ProcessWatch>) -> bool {
    this_boots(owner.boot)
        && match watch {
            Some(w) => w.running(),
            None => envcloak_sys::process_running(owner.pid, StartTime::from_raw(owner.start_time)),
        }
}

/// Whether `peer` may act as `owner`: it is that process instance, and
/// that instance still runs ([`owner_alive`]). A connection outlives the
/// process that made it when the descriptor was passed on or inherited;
/// on Linux the kernel keeps naming the process that connected, so after
/// it exits, before or after it is reaped, a call on that connection is
/// no one's (macOS closes it instead: the peer changed).
fn owner_may_act(owner: &BackupOwner, watch: Option<&ProcessWatch>, peer: &PeerIdentity) -> bool {
    same_instance(owner, peer) && owner_alive(owner, watch)
}

/// A watch of `peer`'s process instance, refused (`evidence`,
/// `caller_gone`) when that process no longer runs: a call on the
/// connection of a process that exited, reaped or not, begins nothing and
/// opens no lease.
fn watch_of(peer: &PeerIdentity) -> Result<ProcessWatch, RpcError> {
    let w = ProcessWatch::new(peer.pid, peer.start_time);
    if w.running() {
        Ok(w)
    } else {
        Err(RpcError::with_reason(
            ErrorKind::Evidence,
            EvidenceError::CallerGone.token(),
        ))
    }
}

/// The processes of `e`'s chain the restore's session and terminal check
/// looks at ([`SubjectEvidence::terminal_scope`]), as a backup seals them.
fn chain_of(e: &SubjectEvidence) -> Vec<CreatorProcess> {
    e.terminal_scope()
        .iter()
        .map(|a| CreatorProcess {
            pid: a.instance.pid,
            start_time: a.instance.start_time.raw(),
            token: a.instance.pidversion,
            sid: a.sid,
            terminal: a.terminal,
        })
        .collect()
}

/// Whether `caller` shares a session or a terminal with a process of the
/// chain sealed with backup creator `c` that still runs in this boot
/// ([`SubjectEvidence::shares_session_or_terminal`]): read from the
/// backup, so it holds after a restart of the daemon.
fn shares_with_creator(caller: &SubjectEvidence, c: &BackupCreator) -> bool {
    if !this_boots(c.owner.boot) {
        return false;
    }
    let scope: Vec<Ancestor> = c
        .chain
        .iter()
        .map(|p| Ancestor {
            instance: ProcessInstance {
                pid: p.pid,
                start_time: StartTime::from_raw(p.start_time),
                pidversion: p.token,
                exe: None,
            },
            sid: p.sid,
            terminal: p.terminal,
            agent: None,
        })
        .collect();
    caller.shares_session_or_terminal(&scope, &running)
}

/// A backup in progress's writer, shared by the calls that use it. Boxed,
/// so the writer stays where it was made until it is dropped: a move would
/// leave its hasher's state behind in freed memory.
type SharedWriter = Arc<Mutex<Option<Box<FileBackupV2Writer>>>>;

/// A backup in progress.
struct Upload {
    owner: BackupOwner,
    /// Its creator's process, watched for its exit.
    watch: ProcessWatch,
    /// The root of its creator's subject: at most
    /// [`MAX_UPLOADS_PER_ROOT`] are in progress for one.
    root: ProcessInstance,
    writer: SharedWriter,
    subject: SubjectSummary,
    purpose: BackupPurpose,
    /// Awake time of its last call.
    last_used: Duration,
}

/// A lease's backup, opened and checked, and its recorded results.
type Leased = (Arc<FileBackupV2Reader>, Arc<Vec<Option<[u8; 32]>>>);

/// A restore lease.
struct Lease {
    owner: BackupOwner,
    /// Its process, watched for its exit.
    watch: ProcessWatch,
    /// The caller's controlling terminal at the proof.
    terminal: Option<u64>,
    reader: Arc<FileBackupV2Reader>,
    results: Arc<Vec<Option<[u8; 32]>>>,
    /// Awake time of its last use.
    last_used: Duration,
}

/// The daemon's backups v2 in memory: those in progress and the restore
/// leases. Lives in [`State`], under its lock. Who made a backup is in
/// the backup, sealed, not here.
#[derive(Default)]
pub struct Registry {
    uploads: HashMap<FileBackupId, Upload>,
    leases: HashMap<FileBackupId, Lease>,
    /// The creators of committed backups whose results are not all
    /// recorded, watched from their upload on: at most
    /// [`MAX_CREATOR_WATCHES`], each dropped once its process exited or
    /// its backup's results are all in.
    creators: HashMap<FileBackupId, ProcessWatch>,
    /// Bumped at every lock: a call that began before one (a restore, a
    /// result, a listing) ends without its effect.
    locks: u64,
}

impl core::fmt::Debug for Registry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Registry")
            .field("uploads", &self.uploads.len())
            .field("leases", &self.leases.len())
            .field("creators", &self.creators.len())
            .finish_non_exhaustive()
    }
}

impl Registry {
    /// A lock ends every backup in progress (their staging directories
    /// go) and every restore lease. The creators' watches stay: they hold
    /// nothing of the vault.
    pub fn on_lock(&mut self) {
        self.uploads.clear();
        self.leases.clear();
        self.locks += 1;
    }

    /// Drops the backups in progress whose creator exited or that went
    /// [`UPLOAD_IDLE`] without a call, the leases whose process exited or
    /// that sat idle for [`LEASE_IDLE`], at awake time `awake`, and the
    /// watches of creators that exited. Exited means reaped or not.
    pub fn sweep(&mut self, awake: Duration) {
        self.uploads.retain(|_, u| {
            awake.saturating_sub(u.last_used) <= UPLOAD_IDLE
                && owner_alive(&u.owner, Some(&u.watch))
        });
        self.leases.retain(|_, l| {
            awake.saturating_sub(l.last_used) <= LEASE_IDLE && owner_alive(&l.owner, Some(&l.watch))
        });
        self.creators.retain(|_, w| w.running());
    }

    /// The backup of `lease` for `peer` on controlling terminal
    /// `terminal` (the outer `None` when its process could not be read)
    /// at awake time `awake`, the lease counting as used then: `None`
    /// unless the lease is that process's, while it runs, on the terminal
    /// of its proof, and has not sat idle past [`LEASE_IDLE`] (an idle one
    /// ends here).
    fn lease_for(
        &mut self,
        lease: &FileBackupId,
        peer: &PeerIdentity,
        terminal: Option<Option<u64>>,
        awake: Duration,
    ) -> Option<Leased> {
        let l = self.leases.get_mut(lease)?;
        if !owner_may_act(&l.owner, Some(&l.watch), peer) || terminal != Some(l.terminal) {
            return None;
        }
        if awake.saturating_sub(l.last_used) > LEASE_IDLE {
            self.leases.remove(lease);
            return None;
        }
        l.last_used = awake;
        Some((Arc::clone(&l.reader), Arc::clone(&l.results)))
    }

    /// Whether `lease` still serves `peer` on terminal `terminal` at awake
    /// time `awake`, as [`Registry::lease_for`] asks, without counting a
    /// use: checked again once a chunk is read, just before it goes out.
    fn lease_stands(
        &self,
        lease: &FileBackupId,
        peer: &PeerIdentity,
        terminal: Option<Option<u64>>,
        awake: Duration,
    ) -> bool {
        self.leases.get(lease).is_some_and(|l| {
            owner_may_act(&l.owner, Some(&l.watch), peer)
                && terminal == Some(l.terminal)
                && awake.saturating_sub(l.last_used) <= LEASE_IDLE
        })
    }
}

/// The controlling terminal of `peer`'s process now, read for its pid
/// only while that pid still has the start time the kernel gave at
/// accept: `None` when it cannot be read so.
fn terminal_now(peer: &PeerIdentity) -> Option<Option<u64>> {
    envcloak_sys::proc_info(peer.pid)
        .ok()
        .filter(|i| i.start_time == peer.start_time)
        .map(|i| i.controlling_tty)
}

fn invalid() -> RpcError {
    RpcError::new(ErrorKind::InvalidParams)
}

fn parse_id(s: &str) -> Result<FileBackupId, RpcError> {
    FileBackupId::parse(s).ok_or(RpcError::new(ErrorKind::NoSuchBackup))
}

/// 64 lowercase hex characters as 32 bytes.
fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        out[i] = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(2 * bytes.len()), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// A backup's failure to be written or read, as the protocol reports it.
/// Nothing of the file's contents is in it.
fn backup_error(e: &VaultError) -> RpcError {
    match e.kind() {
        VaultErrorKind::NotFound => RpcError::new(ErrorKind::NoSuchBackup),
        VaultErrorKind::InvalidRecord => invalid(),
        VaultErrorKind::TooLarge => {
            RpcError::with_reason(ErrorKind::FilesBackupFailed, "too_large")
        }
        VaultErrorKind::Tampered | VaultErrorKind::ReadOnly => {
            RpcError::new(ErrorKind::VaultTampered)
        }
        VaultErrorKind::BackupDamaged => {
            log_line!(
                "envcloakd: a file backup v2 does not open whole (damaged); nothing was read"
            );
            RpcError::new(ErrorKind::FilesBackupFailed)
        }
        k => {
            log_line!(
                "envcloakd: a file backup v2 could not be written or read ({})",
                vault_reason(k)
            );
            RpcError::new(ErrorKind::FilesBackupFailed)
        }
    }
}

/// SHA-256 of the evidence the daemon read for a backup's creator: its
/// kind, whether its chain was cut and has a terminal, each process of
/// the chain (pid, start time, pid version, session, terminal, executable
/// path, agent), and the markers it claimed.
fn evidence_digest(e: &SubjectEvidence) -> [u8; 32] {
    fn opt(h: &mut Sha256, v: Option<&[u8]>) {
        match v {
            None => h.update([0u8]),
            Some(b) => {
                h.update([1u8]);
                h.update(u32::try_from(b.len()).unwrap_or(u32::MAX).to_be_bytes());
                h.update(b);
            }
        }
    }
    let mut h = Sha256::new();
    h.update(b"envcloak/v1/backup-creator-evidence\0");
    h.update([kind_of(e) as u8, u8::from(e.cut()), u8::from(e.terminal())]);
    h.update(
        u32::try_from(e.chain().len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for a in e.chain() {
        h.update(a.instance.pid.to_be_bytes());
        h.update(a.instance.start_time.raw().to_be_bytes());
        opt(
            &mut h,
            a.instance
                .pidversion
                .map(i32::to_be_bytes)
                .as_ref()
                .map(|b| &b[..]),
        );
        opt(&mut h, a.sid.map(i32::to_be_bytes).as_ref().map(|b| &b[..]));
        opt(
            &mut h,
            a.terminal.map(u64::to_be_bytes).as_ref().map(|b| &b[..]),
        );
        let exe = a
            .instance
            .exe
            .as_ref()
            .map(|x| x.path.as_os_str().as_encoded_bytes().to_vec());
        opt(&mut h, exe.as_deref());
        opt(&mut h, a.agent.as_ref().map(|l| l.id.as_bytes()));
    }
    for m in e.claims().markers() {
        opt(&mut h, Some(m.as_bytes()));
    }
    h.finalize().into()
}

fn kind_of(e: &SubjectEvidence) -> CreatorKind {
    match e.kind() {
        SubjectKind::Terminal => CreatorKind::Terminal,
        SubjectKind::Agent => CreatorKind::Agent,
        SubjectKind::Unknown => CreatorKind::Unknown,
    }
}

/// The agent's label as a backup keeps it: at most [`MAX_LABEL_V2`]
/// bytes, cut at a character boundary.
fn label_of(e: &SubjectEvidence) -> Option<String> {
    e.label().map(|l| {
        let mut end = l.name.len().min(MAX_LABEL_V2);
        while !l.name.is_char_boundary(end) {
            end -= 1;
        }
        l.name[..end].to_owned()
    })
}

fn wall_secs(shared: &Shared) -> u64 {
    shared
        .clocks
        .wall()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The unlocked vault's backups v2, to open outside the state lock (a
/// backup's metadata is read and opened there, up to 17 MB of it), and
/// the count of locks it was taken at.
fn backups_of(shared: &Shared) -> Result<(FileBackupsV2, u64), RpcError> {
    let mut s = locked(&shared.state);
    let b = s
        .unlocked()?
        .file_backups_v2()
        .map_err(|e| backup_error(&e))?;
    Ok((b, s.backups().locks))
}

/// Opens backup `id`, outside the state lock.
fn open_reader(shared: &Shared, id: &FileBackupId) -> Result<FileBackupV2Reader, RpcError> {
    let (b, _) = backups_of(shared)?;
    b.open(id).map_err(|e| backup_error(&e))
}

/// A committed backup's answer to a caller that may not change it, or to
/// its creator: `backup_frozen` for the creator, `not_backup_owner` for
/// anyone else, `no_such_backup` when there is none.
fn not_in_progress(shared: &Shared, id: &FileBackupId, peer: &PeerIdentity) -> RpcError {
    match open_reader(shared, id) {
        Ok(r) if owner_may_act(&r.meta().creator.owner, None, peer) => {
            RpcError::new(ErrorKind::BackupFrozen)
        }
        Ok(_) => RpcError::new(ErrorKind::NotBackupOwner),
        Err(e) => e,
    }
}

/// The writer of backup `id` in progress, for its creator only; the
/// upload counts as used now.
fn writer_for(
    shared: &Shared,
    id: &FileBackupId,
    peer: &PeerIdentity,
) -> Result<(SharedWriter, SubjectSummary, BackupPurpose), RpcError> {
    {
        let mut s = locked(&shared.state);
        s.unlocked()?;
        let awake = shared.clocks.awake();
        match s.backups().uploads.get_mut(id) {
            Some(u) if owner_may_act(&u.owner, Some(&u.watch), peer) => {
                u.last_used = awake;
                return Ok((Arc::clone(&u.writer), u.subject.clone(), u.purpose));
            }
            Some(_) => return Err(RpcError::new(ErrorKind::NotBackupOwner)),
            None => {}
        }
    }
    Err(not_in_progress(shared, id, peer))
}

/// `backup.v2.begin`. See the module documentation.
pub fn begin(
    shared: &Shared,
    peer: &PeerIdentity,
    p: BackupBeginParams,
) -> Result<BackupBegunView, RpcError> {
    let purpose = BackupPurpose::from_token(&p.purpose).ok_or_else(invalid)?;
    if !this_boots(this_boot()) {
        // Linux without a boot id: no owner could be told from a process
        // of a later boot.
        log_line!("envcloakd: the boot id cannot be read; no file backup v2 is begun");
        return Err(RpcError::new(ErrorKind::FilesBackupFailed));
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute());
    let data_dir = locked(&shared.state).paths().data_dir.clone();
    let mut plan = Vec::with_capacity(p.files.len());
    for f in p.files {
        if !allowed_path(&f.path, home.as_deref(), &data_dir) {
            return Err(invalid());
        }
        // The permission bits only: a set-user-id, set-group-id or sticky
        // bit an agent declared is never handed back for a restore to set.
        plan.push(PlannedFile {
            path: f.path,
            mode: f.mode & 0o777,
            size: f.size,
        });
    }
    check_plan(&plan).map_err(|e| backup_error(&e))?;
    refuse_if_traced()?;
    let caller = evidence(shared, peer, &p.claims)?;
    let watch = watch_of(peer)?;
    let kind = kind_of(&caller);
    let creator = BackupCreator {
        kind,
        evidence_digest: evidence_digest(&caller),
        agent: label_of(&caller),
        owner: owner_of(peer),
        chain: chain_of(&caller),
    };
    let now = wall_secs(shared);
    let mut s = locked(&shared.state);
    s.unlocked()?;
    s.backups().sweep(shared.clocks.awake());
    let root = caller.root();
    let of_root = s
        .backups()
        .uploads
        .values()
        .filter(|u| u.root == root)
        .count();
    if s.backups().uploads.len() >= MAX_UPLOADS || of_root >= MAX_UPLOADS_PER_ROOT {
        return Err(RpcError::new(ErrorKind::Busy));
    }
    let v = s.unlocked()?;
    if let Err(e) = purge_file_backups_v2(v.paths(), now) {
        log_line!(
            "envcloakd: old file backups v2 could not be removed ({})",
            vault_reason(e.kind())
        );
    }
    let w = v
        .begin_file_backup_v2(purpose, creator, plan, now)
        .map_err(|e| backup_error(&e))?;
    let id = w.id();
    let upload = Upload {
        owner: owner_of(peer),
        watch,
        root,
        writer: Arc::new(Mutex::new(Some(Box::new(w)))),
        subject: subject_summary(peer, &caller),
        purpose,
        last_used: shared.clocks.awake(),
    };
    s.backups().uploads.insert(id, upload);
    Ok(BackupBegunView {
        id: id.to_string(),
        chunk_size: u32::try_from(CHUNK_V2).unwrap_or(u32::MAX),
    })
}

/// `backup.v2.put`.
pub fn put(
    shared: &Shared,
    peer: &PeerIdentity,
    p: BackupPutParams,
) -> Result<BackupPutView, RpcError> {
    let data = p.data.into_inner();
    let id = parse_id(&p.id)?;
    refuse_if_traced()?;
    let (writer, _, _) = writer_for(shared, &id, peer)?;
    let last = {
        let mut g = locked(&writer);
        let w = g.as_mut().ok_or(RpcError::new(ErrorKind::NoSuchBackup))?;
        w.put(
            usize::try_from(p.file).map_err(|_| invalid())?,
            u64::from(p.chunk),
            &data,
        )
        .map_err(|e| backup_error(&e))?
    };
    envcloak_sys::pause_point("backup.v2.put");
    // A lock, or the owner's exit, while the chunk was written ended the
    // backup: the answer says so, never that the chunk is in.
    still_in_progress(&mut locked(&shared.state), &id, &writer)?;
    Ok(BackupPutView { last })
}

/// Fails unless `writer` is still backup `id`'s in progress, the vault
/// unlocked and the owner alive: a call that took the writer before a
/// lock (which drops every backup in progress) or before its owner
/// exited reports the backup ended (`vault_locked`, `no_such_backup`).
fn still_in_progress(
    s: &mut State,
    id: &FileBackupId,
    writer: &SharedWriter,
) -> Result<(), RpcError> {
    s.unlocked()?;
    match s.backups().uploads.get(id) {
        Some(u) if Arc::ptr_eq(&u.writer, writer) && owner_alive(&u.owner, Some(&u.watch)) => {
            Ok(())
        }
        _ => Err(RpcError::new(ErrorKind::NoSuchBackup)),
    }
}

/// `backup.v2.commit`.
pub fn commit(
    shared: &Shared,
    peer: &PeerIdentity,
    p: BackupIdParams,
) -> Result<BackupCommittedView, RpcError> {
    let id = parse_id(&p.id)?;
    let (writer, subject, purpose) = writer_for(shared, &id, peer)?;
    {
        let mut g = locked(&writer);
        let w = g.as_mut().ok_or(RpcError::new(ErrorKind::NoSuchBackup))?;
        w.seal().map_err(|e| backup_error(&e))?;
    }
    envcloak_sys::pause_point("backup.v2.commit");
    // The backup is put in place under the state lock, only while it is
    // still in progress: a lock while the metadata was sealed ended it,
    // and a lock now waits until it is in place. Either way the upload
    // goes, and with its last handle the writer (and a staging directory
    // never put in place).
    let mut s = locked(&shared.state);
    let installed = still_in_progress(&mut s, &id, &writer).and_then(|()| {
        let mut g = locked(&writer);
        let w = g.as_mut().ok_or(RpcError::new(ErrorKind::NoSuchBackup))?;
        w.install().map_err(|e| backup_error(&e))
    });
    let upload = s.backups().uploads.remove(&id);
    let done = installed?;
    // The creator stays watched while the backup awaits its results.
    let reg = s.backups();
    if let Some(u) = upload {
        if reg.creators.len() < MAX_CREATOR_WATCHES {
            reg.creators.insert(id, u.watch);
        }
    }
    s.audit(AuditEvent::BackupV2Committed {
        pid: peer.pid,
        subject,
        backup: id.to_string(),
        purpose: purpose.as_str(),
        files: done.files,
    });
    Ok(BackupCommittedView {
        id: id.to_string(),
        files: u32::try_from(done.files).unwrap_or(u32::MAX),
        bytes: done.bytes,
        created_secs: done.created_at,
    })
}

/// `backup.v2.record_result`. The result is put in place under the state
/// lock, only while the vault is unlocked under the lock count the backup
/// was opened at and the creator still runs: a lock meanwhile records
/// nothing (`vault_locked`), and a lock after that waits until it is in
/// place.
pub fn record_result(
    shared: &Shared,
    peer: &PeerIdentity,
    p: BackupResultParams,
) -> Result<BackupResultView, RpcError> {
    let id = parse_id(&p.id)?;
    let after = parse_sha256(&p.sha256_after).ok_or_else(invalid)?;
    let file = usize::try_from(p.file).map_err(|_| invalid())?;
    {
        let mut s = locked(&shared.state);
        s.unlocked()?;
        if let Some(u) = s.backups().uploads.get(&id) {
            // Not committed yet: there is nothing to record a result for.
            return Err(if owner_may_act(&u.owner, Some(&u.watch), peer) {
                invalid()
            } else {
                RpcError::new(ErrorKind::NotBackupOwner)
            });
        }
    }
    let (b, locks) = backups_of(shared)?;
    let reader = b.open(&id).map_err(|e| backup_error(&e));
    drop(b);
    let reader = reader?;
    // From the creator, while it lives (D-07): once it has exited, reaped
    // or not, the backup stays `result_unrecorded`, whoever holds its
    // connection.
    let creator_may_act = |s: &mut State| {
        owner_may_act(
            &reader.meta().creator.owner,
            s.backups().creators.get(&id),
            peer,
        )
    };
    if !creator_may_act(&mut locked(&shared.state)) {
        return Err(RpcError::new(ErrorKind::NotBackupOwner));
    }
    envcloak_sys::pause_point("backup.v2.record_result");
    {
        let mut s = locked(&shared.state);
        s.unlocked()?;
        if s.backups().locks != locks {
            return Err(RpcError::new(ErrorKind::VaultLocked));
        }
        if !creator_may_act(&mut s) {
            return Err(RpcError::new(ErrorKind::NotBackupOwner));
        }
        reader
            .record_result(file, &after)
            .map_err(|e| match e.kind() {
                VaultErrorKind::AlreadyExists => RpcError::new(ErrorKind::BackupFrozen),
                _ => backup_error(&e),
            })?;
    }
    let results = reader.results().map_err(|e| backup_error(&e))?;
    let recorded = results.iter().filter(|r| r.is_some()).count();
    let complete = recorded == results.len();
    if complete {
        locked(&shared.state).backups().creators.remove(&id);
    }
    Ok(BackupResultView {
        recorded: u32::try_from(recorded).unwrap_or(u32::MAX),
        complete,
    })
}

/// Where a committed backup stands, from its results and whether its
/// creator still runs (worked out each time: L-09).
fn state_of(r: &FileBackupV2Reader, results: &[Option<[u8; 32]>]) -> BackupStateView {
    if results.iter().all(Option::is_some) {
        BackupStateView::Complete
    } else if owner_alive(&r.meta().creator.owner, None) {
        BackupStateView::AwaitingResult
    } else {
        BackupStateView::ResultUnrecorded
    }
}

fn creator_view(c: &BackupCreator) -> BackupCreatorView {
    BackupCreatorView {
        kind: c.kind.as_str().to_owned(),
        agent: c.agent.clone(),
        pid: c.owner.pid,
    }
}

fn file_view(
    r: &FileBackupV2Reader,
    results: &[Option<[u8; 32]>],
    i: usize,
) -> Option<RestoreFileView> {
    let f = r.meta().files.get(i)?;
    Some(RestoreFileView {
        file: u32::try_from(i).ok()?,
        path: f.path.clone(),
        mode: f.mode,
        size: f.size,
        chunks: chunks_of(f.size),
        sha256: hex(&f.sha256),
        sha256_after: results.get(i).copied().flatten().map(|h| hex(&h)),
    })
}

/// The most bytes `s` takes as a JSON string's contents: a control
/// character is escaped as `\u00XX`, a quote or a backslash as two.
fn json_len(s: &str) -> usize {
    s.bytes()
        .map(|b| match b {
            0..=0x1f => 6,
            b'"' | b'\\' => 2,
            _ => 1,
        })
        .sum()
}

/// The statement of a backup: every file's view while the paths, as JSON,
/// fit [`STATEMENT_BUDGET`], so the answer always fits in one frame.
fn statement(
    r: &FileBackupV2Reader,
    results: &[Option<[u8; 32]>],
    state: BackupStateView,
) -> RestoreStatementView {
    let m = r.meta();
    let mut files = Vec::new();
    let mut used = 0usize;
    for i in 0..m.files.len() {
        let Some(f) = file_view(r, results, i) else {
            break;
        };
        used += json_len(&f.path) + 256;
        if used > STATEMENT_BUDGET {
            break;
        }
        files.push(f);
    }
    RestoreStatementView {
        id: m.id.to_string(),
        created_secs: m.created_at,
        purpose: m.purpose.as_str().to_owned(),
        creator: creator_view(&m.creator),
        state,
        files,
        files_total: u32::try_from(m.files.len()).unwrap_or(u32::MAX),
        bytes: m.files.iter().map(|f| f.size).sum(),
    }
}

/// `backup.v2.open_restore`. See the module documentation.
pub fn open_restore(
    shared: &Shared,
    peer: &PeerIdentity,
    p: OpenRestoreParams,
) -> Result<RestoreLeaseView, RpcError> {
    const METHOD: &str = "backup.v2.open_restore";
    let pass = p.passphrase.into_inner();
    let id = parse_id(&p.id)?;
    refuse_if_traced()?;
    let caller = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover(shared, peer, &caller, METHOD)?;
    let watch = watch_of(peer)?;
    // What the backup is, before the passphrase is looked at.
    let (reader, results) = {
        let r = open_reader(shared, &id)?;
        let results = r.results().map_err(|e| backup_error(&e))?;
        // The approval-origin boundary, as for a pending request: not from
        // a session or terminal of the chain of the agent or unknown process
        // that made the backup, while a process of it runs.
        let c = &r.meta().creator;
        if c.kind != CreatorKind::Terminal && shares_with_creator(&caller, c) {
            let r = ProofRefusal::RequesterTerminal;
            shared.audit(AuditEvent::ProofRefused {
                pid: peer.pid,
                method: METHOD,
                reason: r.token(),
            });
            return Err(RpcError::with_reason(ErrorKind::ProofRefused, r.token()));
        }
        (Arc::new(r), Arc::new(results))
    };
    let state = state_of(&reader, &results);
    let by_agent = reader.meta().creator.kind != CreatorKind::Terminal;
    let unrecorded = state != BackupStateView::Complete;
    if unrecorded && !p.unrecorded {
        return Err(RpcError::with_reason(
            ErrorKind::RestoreRefused,
            "result_unrecorded",
        ));
    }
    if by_agent && !p.created_by_agent_ticked {
        return Err(RpcError::with_reason(
            ErrorKind::RestoreRefused,
            "created_by_agent",
        ));
    }
    // One proof: one Argon2id run.
    let (mut s, caller) = prove_as(shared, peer, caller, AuditKind::RestoreV2, |v| {
        v.verify_passphrase(&pass)
    })?;
    drop(pass);
    let locks = s.backups().locks;
    drop(s);
    // The whole backup is checked before a lease exists: a backup that
    // does not open whole is never restored in part.
    reader.verify().map_err(|e| backup_error(&e))?;
    envcloak_sys::pause_point("backup.v2.open_restore");
    // A lock since the proof, the vault unlocked again or not, issues no
    // lease.
    let mut s = locked(&shared.state);
    s.unlocked()?;
    if s.backups().locks != locks {
        return Err(RpcError::new(ErrorKind::VaultLocked));
    }
    s.backups().sweep(shared.clocks.awake());
    if s.backups().leases.len() >= MAX_LEASES {
        return Err(RpcError::new(ErrorKind::Busy));
    }
    let form = match (by_agent, unrecorded) {
        (true, true) => Some("created_by_agent+unrecorded"),
        (true, false) => Some("created_by_agent"),
        (false, true) => Some("unrecorded"),
        (false, false) => None,
    };
    // A delivery: the entry is on disk before the lease exists, so before
    // the first chunk; when it cannot be written, no lease is issued.
    let entry = AuditEvent::RestoreV2Opened {
        pid: peer.pid,
        subject: subject_summary(peer, &caller),
        backup: id.to_string(),
        files: reader.meta().files.len(),
        form,
    };
    if !s.audit_delivery(entry) {
        return Err(RpcError::new(ErrorKind::AuditFailed));
    }
    let lease = FileBackupId::generate();
    let awake = shared.clocks.awake();
    let view = statement(&reader, &results, state);
    s.backups().leases.insert(
        lease,
        Lease {
            owner: owner_of(peer),
            watch,
            terminal: caller.chain().first().and_then(|a| a.terminal),
            reader,
            results,
            last_used: awake,
        },
    );
    s.touch(Reading::now(&shared.clocks));
    Ok(RestoreLeaseView {
        lease: lease.to_string(),
        statement: view,
    })
}

/// `backup.v2.read`.
pub fn read(
    shared: &Shared,
    peer: &PeerIdentity,
    p: BackupReadParams,
) -> Result<BackupChunk, RpcError> {
    let none = || RpcError::new(ErrorKind::NoSuchLease);
    let lease = FileBackupId::parse(&p.lease).ok_or_else(none)?;
    refuse_if_traced()?;
    let (reader, results) = {
        let terminal = terminal_now(peer);
        let awake = shared.clocks.awake();
        let mut s = locked(&shared.state);
        s.backups()
            .lease_for(&lease, peer, terminal, awake)
            .ok_or_else(none)?
    };
    let file = usize::try_from(p.file).map_err(|_| invalid())?;
    let (data, last) = reader
        .chunk(file, u64::from(p.chunk))
        .map_err(|e| backup_error(&e))?;
    envcloak_sys::pause_point("backup.v2.read");
    // A delivery (SPEC "Lock"): the chunk goes out only while the lease
    // still stands, checked under the state lock after it was read, with
    // the caller's terminal and the clocks read again. A lock, the lease's
    // end, its owner's exit, a move to another terminal or a read that
    // outlasted the idle limit meanwhile delivers nothing.
    {
        let terminal = terminal_now(peer);
        let awake = shared.clocks.awake();
        let mut s = locked(&shared.state);
        let standing =
            s.unlocked().is_ok() && s.backups().lease_stands(&lease, peer, terminal, awake);
        if !standing {
            return Err(none());
        }
    }
    Ok(BackupChunk {
        data: WireSecret::new(data),
        last,
        file: if p.chunk == 0 {
            file_view(&reader, &results, file)
        } else {
            None
        },
    })
}

/// `backup.v2.list`. The backups are opened outside the state lock; a
/// lock while they are read ends the call (`vault_locked`) before the next
/// one is opened, and the copy of the `backup` subkey goes with it.
pub fn list(shared: &Shared, _p: NoParams) -> Result<BackupListView, RpcError> {
    let open_leases = {
        let mut s = locked(&shared.state);
        s.backups().sweep(shared.clocks.awake());
        u32::try_from(s.backups().leases.len()).unwrap_or(u32::MAX)
    };
    let (b, locks) = backups_of(shared)?;
    let mut found = list_file_backups_v2(b.paths()).map_err(|e| backup_error(&e))?;
    found.reverse();
    let truncated = found.len() > MAX_LISTED;
    found.truncate(MAX_LISTED);
    let mut backups = Vec::with_capacity(found.len());
    let still_unlocked = || {
        let mut s = locked(&shared.state);
        s.unlocked().is_ok() && s.backups().locks == locks
    };
    for listed in found {
        if !still_unlocked() {
            return Err(RpcError::new(ErrorKind::VaultLocked));
        }
        backups.push(entry(&b, &listed.id, listed.created_at));
        envcloak_sys::test_event("backup.v2.list opened a backup");
        envcloak_sys::pause_point("backup.v2.list");
    }
    drop(b);
    if !still_unlocked() {
        return Err(RpcError::new(ErrorKind::VaultLocked));
    }
    Ok(BackupListView {
        backups,
        truncated,
        open_leases,
    })
}

fn entry(b: &FileBackupsV2, id: &FileBackupId, created_at: u64) -> BackupEntryView {
    let opened = b
        .open(id)
        .and_then(|r| r.results().map(|results| (r, results)));
    match opened {
        Ok((r, results)) => {
            let m = r.meta();
            BackupEntryView {
                id: id.to_string(),
                created_secs: m.created_at,
                purpose: Some(m.purpose.as_str().to_owned()),
                creator: Some(creator_view(&m.creator)),
                state: state_of(&r, &results),
                files: u32::try_from(m.files.len()).unwrap_or(u32::MAX),
                bytes: m.files.iter().map(|f| f.size).sum(),
            }
        }
        Err(_) => BackupEntryView {
            id: id.to_string(),
            created_secs: created_at,
            purpose: None,
            creator: None,
            state: BackupStateView::Damaged,
            files: 0,
            bytes: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_paths_under_the_allowed_roots_are_taken() {
        let home = Path::new("/h/u");
        let data = Path::new("/h/u/.local/share/envcloak");
        let ok = [
            "/h/u/.claude/settings.json",
            "/h/u/.claude/projects/p/s.jsonl",
            "/h/u/.claude.json",
            "/h/u/.codex/config.toml",
            "/h/u/.codex/sessions/2026/10/02/rollout-1.jsonl",
            "/h/u/.config/opencode/opencode.json",
            "/h/u/.local/share/goose/sessions/x.jsonl",
            "/h/u/.local/share/envcloak/mcp/claude-code-x/envcloak.toml",
            "/src/acme/.env",
            "/src/acme/.env.local",
            "/src/acme/.mcp.json",
            "/src/acme/AGENTS.md",
            "/src/acme/.claude/settings.local.json",
            "/src/acme/.cursor/mcp.json",
            "/src/acme/.vscode/mcp.json",
        ];
        for p in ok {
            assert!(allowed_path(p, Some(home), data), "{p}");
        }
        let refused = [
            "",
            "relative/.env",
            "/h/u/.zshrc",
            "/h/u/.bashrc",
            "/h/u/.ssh/config",
            "/h/u/Library/LaunchAgents/x.plist",
            "/etc/passwd",
            "/h/u/.claude/../.zshrc",
            "/h/u/./.zshrc",
            "/h/u//.zshrc",
            "/h/u/.claude/",
            "/h/u/.claude",
            "/h/u/.config/fish/config.fish",
            "/h/u/.envrc",
            "/h/u/.env.",
            "/h/u/.local/share/envcloak/vault/vault.db",
            "/h/u/.local/share/envcloak/mcp",
            "/src/acme/.vscode/settings.json",
            "/src/acme/.env\0x",
        ];
        for p in refused {
            assert!(!allowed_path(p, Some(home), data), "{p:?}");
        }
        assert!(!allowed_path(
            &format!("/{}", "a".repeat(5000)),
            Some(home),
            data
        ));
        // Without a home, only the rest.
        assert!(!allowed_path("/h/u/.claude.json", None, data));
        assert!(allowed_path("/h/u/.claude/settings.json", None, data));
    }

    /// The statement's budget counts a path as JSON writes it, escapes
    /// included, so a path of control characters cannot push the answer
    /// past a frame.
    #[test]
    fn a_path_is_counted_as_json_writes_it() {
        for s in [
            "/h/.env",
            "/h/\u{1}\u{1f}\"\\/x",
            "/h/\u{e9}\u{20ac}",
            &"\u{7}".repeat(4096),
        ] {
            let written = serde_json::to_string(s).unwrap().len() - 2;
            assert!(json_len(s) >= written, "{s:?}");
        }
    }

    #[test]
    fn hex_digests_parse_only_whole_and_lowercase() {
        let h = [0xab_u8; 32];
        assert_eq!(parse_sha256(&hex(&h)), Some(h));
        assert_eq!(parse_sha256(&hex(&h).to_uppercase()), None);
        assert_eq!(parse_sha256(&hex(&h)[1..]), None);
        assert_eq!(parse_sha256(&format!("{}0", hex(&h))), None);
        assert_eq!(parse_sha256(&"g".repeat(64)), None);
    }

    fn me() -> envcloak_sys::ProcInfo {
        envcloak_sys::proc_info(i32::try_from(std::process::id()).unwrap()).unwrap()
    }

    fn peer_of(i: &envcloak_sys::ProcInfo) -> PeerIdentity {
        PeerIdentity {
            uid: 0,
            pid: i.pid,
            start_time: i.start_time,
            pidversion: None,
            source: envcloak_sys::PeerSource::PeerCred,
        }
    }

    fn lease_of(owner: BackupOwner, terminal: Option<u64>, last_used: Duration) -> Lease {
        Lease {
            owner,
            watch: ProcessWatch::new(owner.pid, StartTime::from_raw(owner.start_time)),
            terminal,
            reader: test_reader(),
            results: Arc::new(Vec::new()),
            last_used,
        }
    }

    /// A lease, an upload and a creator's evidence go with their process;
    /// a lease also after 60 seconds idle (an injected clock).
    #[test]
    fn a_lease_ends_after_60_seconds_idle_or_when_its_process_exits() {
        let me = me();
        let owner = owner_of(&peer_of(&me));
        let gone = BackupOwner {
            start_time: me.start_time.raw() + 1,
            ..owner
        };
        let alive_now = |r: &Registry| r.leases.len();
        let mut reg = Registry::default();
        let t0 = Duration::from_secs(1000);
        for (n, o) in [(1u8, owner), (2, gone)] {
            reg.leases
                .insert(FileBackupId([n; 16]), lease_of(o, None, t0));
        }
        reg.sweep(t0);
        assert_eq!(alive_now(&reg), 1, "the lease of an exited process stays");
        reg.sweep(t0 + LEASE_IDLE);
        assert_eq!(alive_now(&reg), 1, "a lease ended before 60 seconds idle");
        reg.sweep(t0 + LEASE_IDLE + Duration::from_secs(1));
        assert_eq!(alive_now(&reg), 0, "a lease outlived 60 seconds idle");
    }

    /// `read` takes a lease only for its process on the terminal of its
    /// proof and within 60 seconds of its last use, an idle lease ending
    /// there and then; and checks it again with the terminal and clock
    /// read anew before a chunk goes out (injected clock and terminals;
    /// the tick's sweep, which would end an idle lease first, is not
    /// involved).
    #[test]
    fn a_read_takes_a_lease_only_on_its_terminal_and_within_its_idle_limit() {
        let me = me();
        let peer = peer_of(&me);
        let tty = me.controlling_tty;
        let other_tty = Some(Some(tty.map_or(1, |t| t ^ 1)));
        let here = Some(tty);
        let id = FileBackupId([7; 16]);
        let t0 = Duration::from_secs(1000);
        let mut reg = Registry::default();
        reg.leases.insert(id, lease_of(owner_of(&peer), tty, t0));
        // Another terminal, none readable, or another process: refused,
        // and the lease stays.
        assert!(reg.lease_for(&id, &peer, other_tty, t0).is_none());
        assert!(reg.lease_for(&id, &peer, None, t0).is_none());
        let stranger = PeerIdentity {
            start_time: StartTime::from_raw(me.start_time.raw() + 1),
            ..peer
        };
        assert!(reg.lease_for(&id, &stranger, here, t0).is_none());
        assert_eq!(reg.leases.len(), 1);
        // At its idle limit it serves, and counts as used then.
        let used = t0 + LEASE_IDLE;
        assert!(reg.lease_for(&id, &peer, here, used).is_some());
        // Before delivery: only on its terminal, within the limit.
        assert!(reg.lease_stands(&id, &peer, here, used + LEASE_IDLE));
        assert!(!reg.lease_stands(&id, &peer, other_tty, used));
        assert!(!reg.lease_stands(&id, &peer, None, used));
        assert!(!reg.lease_stands(&id, &stranger, here, used));
        assert!(
            !reg.lease_stands(&id, &peer, here, used + LEASE_IDLE + Duration::from_secs(1)),
            "a chunk read past the idle limit went out"
        );
        // Past the limit since its last use: refused, and ended.
        assert!(
            reg.lease_for(&id, &peer, here, used + LEASE_IDLE + Duration::from_secs(1))
                .is_none(),
            "an idle lease served a read"
        );
        assert!(reg.leases.is_empty(), "an idle lease was kept");
    }

    /// An owner-bound call is answered only while the owner runs: a caller
    /// with the pid and start time of a process that has exited (a
    /// connection it passed on before it exited, on Linux) is the owner's
    /// instance but may not act for it.
    #[test]
    fn only_a_live_owner_may_act() {
        let me = me();
        let peer = peer_of(&me);
        let w = ProcessWatch::new(peer.pid, peer.start_time);
        assert!(owner_may_act(&owner_of(&peer), None, &peer));
        assert!(owner_may_act(&owner_of(&peer), Some(&w), &peer));
        let gone = PeerIdentity {
            start_time: StartTime::from_raw(me.start_time.raw() + 1),
            ..peer
        };
        let owner = owner_of(&gone);
        let gw = ProcessWatch::new(gone.pid, gone.start_time);
        assert!(same_instance(&owner, &gone));
        assert!(!owner_may_act(&owner, None, &gone));
        assert!(!owner_may_act(&owner, Some(&gw), &gone));
        assert!(!owner_may_act(&owner, None, &peer));
        assert!(watch_of(&gone).is_err());
        assert!(watch_of(&peer).is_ok());
    }

    /// A creator that exited and is not yet reaped (a zombie) keeps its
    /// pid and start time, but no longer runs: it may not act, by its
    /// watch or by the process table, its upload and lease go at the
    /// sweep, its watch is dropped, and no new watch is taken of it.
    #[test]
    fn an_exited_unreaped_owner_may_not_act() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "read x"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let info = envcloak_sys::proc_info(i32::try_from(child.id()).unwrap()).unwrap();
        let peer = peer_of(&info);
        let owner = owner_of(&peer);
        let t0 = Duration::from_secs(1000);
        let mut reg = Registry::default();
        reg.leases
            .insert(FileBackupId([1; 16]), lease_of(owner, None, t0));
        reg.uploads
            .insert(FileBackupId([2; 16]), upload_of(owner, t0));
        reg.creators.insert(
            FileBackupId([3; 16]),
            ProcessWatch::new(peer.pid, peer.start_time),
        );
        let watch = watch_of(&peer).unwrap();
        assert!(owner_may_act(&owner, Some(&watch), &peer));
        assert!(owner_may_act(&owner, None, &peer));
        reg.sweep(t0);
        assert_eq!(
            (reg.leases.len(), reg.uploads.len(), reg.creators.len()),
            (1, 1, 1)
        );
        drop(child.stdin.take());
        let end = std::time::Instant::now() + Duration::from_secs(10);
        while envcloak_sys::process_running(peer.pid, peer.start_time) {
            assert!(std::time::Instant::now() < end, "the child never exited");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Not reaped yet: the process table still has it.
        assert_eq!(
            envcloak_sys::proc_info(peer.pid).unwrap().start_time,
            peer.start_time
        );
        assert!(!owner_may_act(&owner, Some(&watch), &peer));
        assert!(!owner_may_act(&owner, None, &peer));
        assert!(watch_of(&peer).is_err());
        reg.sweep(t0);
        assert_eq!(
            (reg.leases.len(), reg.uploads.len(), reg.creators.len()),
            (0, 0, 0)
        );
        child.wait().unwrap();
    }

    /// A process instance recorded in another boot is neither alive nor
    /// the caller, whatever its pid and start time: on Linux a start time
    /// counts from boot, and a process of a later boot can have both again.
    #[test]
    fn an_owner_of_another_boot_is_neither_alive_nor_the_caller() {
        let peer = peer_of(&me());
        let here = owner_of(&peer);
        let w = ProcessWatch::new(peer.pid, peer.start_time);
        assert!(same_instance(&here, &peer) && owner_alive(&here, None));
        for other in [Some([0xee; 16]), None, Some([0; 16])] {
            if other == this_boot() {
                continue;
            }
            let there = BackupOwner {
                boot: other,
                ..here
            };
            assert!(!owner_alive(&there, None), "{other:?}");
            assert!(!owner_alive(&there, Some(&w)), "{other:?}");
            assert!(!same_instance(&there, &peer), "{other:?}");
        }
    }

    fn upload_of(owner: BackupOwner, last_used: Duration) -> Upload {
        let me = me();
        Upload {
            owner,
            watch: ProcessWatch::new(owner.pid, StartTime::from_raw(owner.start_time)),
            root: ProcessInstance {
                pid: me.pid,
                start_time: me.start_time,
                pidversion: None,
                exe: None,
            },
            writer: Arc::new(Mutex::new(Some(Box::new(test_writer())))),
            subject: SubjectSummary::default(),
            purpose: BackupPurpose::Scrub,
            last_used,
        }
    }

    /// A backup in progress goes when its creator exits, and after
    /// [`UPLOAD_IDLE`] without a call (an injected clock), so no process
    /// holds a slot it does not use.
    #[test]
    fn an_upload_ends_after_its_idle_limit_or_when_its_creator_exits() {
        let me = me();
        let owner = owner_of(&peer_of(&me));
        let gone = BackupOwner {
            start_time: me.start_time.raw() + 1,
            ..owner
        };
        let t0 = Duration::from_secs(1000);
        let mut reg = Registry::default();
        for (n, o) in [(1u8, owner), (2, gone)] {
            reg.uploads.insert(FileBackupId([n; 16]), upload_of(o, t0));
        }
        reg.sweep(t0);
        assert_eq!(
            reg.uploads.len(),
            1,
            "the upload of an exited creator stays"
        );
        reg.sweep(t0 + UPLOAD_IDLE);
        assert_eq!(
            reg.uploads.len(),
            1,
            "an upload ended before its idle limit"
        );
        reg.sweep(t0 + UPLOAD_IDLE + Duration::from_secs(1));
        assert_eq!(reg.uploads.len(), 0, "an upload outlived its idle limit");
    }

    /// Runs `f` on this thread's vault for the unit tests' backups, made
    /// once per thread.
    fn with_test_vault<R>(f: impl FnOnce(&envcloak_core::vault::Vault) -> R) -> R {
        thread_local! {
            static VAULT: (tempfile::TempDir, envcloak_core::vault::Vault) = {
                let dir = tempfile::tempdir().unwrap();
                let paths = envcloak_core::vault::VaultPaths::under(dir.path().join("data"));
                let (v, _) = envcloak_core::create_vault(
                    &paths,
                    &envcloak_core::SecretBytes::copy_from(b"a test passphrase, not a fixture"),
                    envcloak_core::crypto::KdfParams::minimum(),
                )
                .unwrap();
                (dir, v)
            };
        }
        VAULT.with(|(_, v)| f(v))
    }

    fn test_writer() -> FileBackupV2Writer {
        with_test_vault(|v| {
            v.begin_file_backup_v2(
                BackupPurpose::Scrub,
                BackupCreator {
                    kind: CreatorKind::Terminal,
                    evidence_digest: [0; 32],
                    agent: None,
                    owner: BackupOwner {
                        pid: 1,
                        start_time: 1,
                        token: None,
                        boot: None,
                    },
                    chain: Vec::new(),
                },
                vec![PlannedFile {
                    path: "/h/.env".into(),
                    mode: 0o600,
                    size: 0,
                }],
                1_790_000_000,
            )
            .unwrap()
        })
    }

    fn test_reader() -> Arc<FileBackupV2Reader> {
        let mut w = test_writer();
        w.put(0, 0, &envcloak_core::SecretBytes::copy_from(b""))
            .unwrap();
        let id = w.commit().unwrap().id;
        Arc::new(with_test_vault(|v| v.open_file_backup_v2(&id).unwrap()))
    }
}
