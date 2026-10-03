//! How the installer changes an agent's files (M2 plan M2-08, D-16;
//! lesson L-11; SPEC §6.4 "Backups" and "Modifying a file"), and what it
//! records so `agents uninstall` removes exactly what it added.
//!
//! One change to one file:
//! 1. The file is read beneath its directory, never through a symlink;
//!    a symlink, a file with another hard link, one that is not a regular
//!    file of this user, and one over [`MAX_FILE`] are refused and
//!    reported, never changed.
//! 2. The new contents are worked out; the same contents change nothing.
//! 3. A file the host rewrites itself (Claude Code's `settings.json`,
//!    Codex's `config.toml`) is changed only while it is open in no other
//!    process and was not modified in the last 2 minutes: quit the agent
//!    first (D-16). A file whose stamp (device, inode, size, modification
//!    and change times) is still the one EnvCloak recorded right after its
//!    own last write is not held to the 2 minutes, so `agents install`
//!    and an EnvCloak edit right after it work without waiting.
//! 4. An existing file is backed up first, as a backup v2 the daemon
//!    seals (purpose `agents`); with no backup, nothing is changed.
//! 5. The file is replaced in one step, and only if it is still the file
//!    read (`envcloak_scan::replace_atomically`: its stamp checked again,
//!    change time included, just before the swap); a new file is created
//!    only if its name is still free. The backup's result (the SHA-256 of
//!    what the change left) is recorded with the daemon.
//! 6. The new stamp, the exact splice made and the edits it stands for
//!    are kept in EnvCloak's state file ([`State`]), `<data>/agents/
//!    state.json`.
//!
//! Undoing a file: while it is byte for byte what EnvCloak last left
//! (its SHA-256), the splices are undone in reverse, which gives back the
//! file as it was before the first install, byte for byte, or removes a
//! file EnvCloak created. A file changed since (the host rewrote it, the
//! person edited it) has EnvCloak's edits taken out by structure instead
//! (a block, an array element, a key), and everything else kept.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::DirBuilder;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use envcloak_core::SecretBytes;
use envcloak_ipc::proto::{BackupBeginParams, BackupPlanFile};
use envcloak_scan::{
    FileStamp, MIN_AGE, ModifyError, ScanErrorKind, ScanRoot, create_atomically, open_root,
    read_plain, remove_checked_at, replace_atomically,
};
use envcloak_sys::InUse;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::jsonedit::{Splice, splice};

/// The largest file the installer reads (1 MiB).
pub const MAX_FILE: usize = 1024 * 1024;
/// The largest state file read (8 MiB).
const MAX_STATE: usize = 8 * 1024 * 1024;

/// Why a file was not changed. Value-free: a name and a fixed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub name: &'static str,
    pub message: String,
}

impl Refusal {
    pub fn new(name: &'static str, message: impl Into<String>) -> Self {
        Refusal {
            name,
            message: message.into(),
        }
    }

    fn scan(k: ScanErrorKind) -> Self {
        Refusal::new(k.token(), k.message())
    }

    fn modify(e: &ModifyError) -> Self {
        Refusal::new(e.kind.token(), e.kind.message())
    }
}

/// One structural edit, kept so it can be taken out of a file changed
/// since by its host or its person.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Edit {
    /// EnvCloak's Markdown block.
    Block,
    /// An element added to a JSON array, `created` of `path`'s last keys
    /// made for it.
    JsonElement {
        path: Vec<String>,
        value: Value,
        created: usize,
    },
    /// A TOML value set at `path` (its leaves, as JSON), and what was
    /// there before, `created` of `path`'s last keys made for it.
    TomlValue {
        path: Vec<String>,
        value: Value,
        previous: Option<Value>,
        created: usize,
    },
    /// A file that is EnvCloak's whole.
    WholeFile,
}

/// A file's [`FileStamp`], as kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stamp {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
    pub ctime_nsec: i64,
    pub mode: u32,
    pub nlink: u64,
    pub uid: u32,
}

impl From<FileStamp> for Stamp {
    fn from(s: FileStamp) -> Self {
        Stamp {
            dev: s.dev,
            ino: s.ino,
            size: s.size,
            mtime: s.mtime,
            mtime_nsec: s.mtime_nsec,
            ctime: s.ctime,
            ctime_nsec: s.ctime_nsec,
            mode: s.mode,
            nlink: s.nlink,
            uid: s.uid,
        }
    }
}

/// A splice, as kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpliceRecord {
    pub at: usize,
    pub old: String,
    pub new: String,
}

/// What EnvCloak did to one file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    /// The host it was done for (`claude-code`, `codex`), or `project`.
    pub host: String,
    /// `global`, or the project directory.
    pub scope: String,
    /// EnvCloak created the file.
    pub created: bool,
    /// The SHA-256 of the file before EnvCloak's first change.
    pub pre_sha256: String,
    /// The SHA-256 of what EnvCloak's last change left.
    pub post_sha256: String,
    /// The stamp right after EnvCloak's last write.
    pub stamp: Stamp,
    /// Every splice made, in order.
    pub splices: Vec<SpliceRecord>,
    /// The edits they stand for.
    pub edits: Vec<Edit>,
}

/// EnvCloak's record of its agent integrations, `<data>/agents/state.json`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub version: u32,
    /// By absolute path.
    pub files: BTreeMap<String, FileRecord>,
    /// The MCP server entries EnvCloak registered through a host's own
    /// command line, by host id.
    #[serde(default)]
    pub mcp: BTreeMap<String, Value>,
    /// Files EnvCloak gave back by an undo, so nothing of its own is left
    /// in them, by absolute path, with the stamp that write left: while a
    /// file's stamp is still this one, EnvCloak's next change of it (an
    /// install right after an uninstall) is its own edit, exempt from the
    /// 2-minute rule like any other (D-16).
    #[serde(default)]
    pub written: BTreeMap<String, Stamp>,
}

/// The state file's format version.
pub const STATE_VERSION: u32 = 1;

/// EnvCloak's agent state, held locked while it is changed.
#[derive(Debug)]
pub struct StateFile {
    dir: ScanRoot,
    pub state: State,
    stamp: Option<FileStamp>,
    _lock: std::fs::File,
}

const STATE_NAME: &str = "state.json";
const LOCK_NAME: &str = "state.lock";

impl StateFile {
    /// Opens (creating `<data>/agents/`, 0700, when missing) and locks the
    /// state in `data_dir`.
    ///
    /// # Errors
    /// When the directory or the state cannot be read, the state is not
    /// one this build reads, or another `agents install` or `uninstall`
    /// holds it.
    pub fn open(data_dir: &Path) -> Result<StateFile, Refusal> {
        let dir = data_dir.join("agents");
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|_| {
                Refusal::new(
                    "state_unreadable",
                    "EnvCloak's agent state directory could not be made",
                )
            })?;
        let root = open_root(&dir).map_err(|_| {
            Refusal::new(
                "state_unreadable",
                "EnvCloak's agent state directory could not be opened",
            )
        })?;
        let lock = envcloak_sys::create_rw_beneath(root.dir(), OsStr::new(LOCK_NAME), 0o600)
            .or_else(|_| envcloak_sys::open_beneath(root.dir(), OsStr::new(LOCK_NAME)))
            .map_err(|_| {
                Refusal::new(
                    "state_unreadable",
                    "EnvCloak's agent state lock could not be opened",
                )
            })?;
        if !envcloak_sys::try_lock_exclusive(&lock).unwrap_or(false) {
            return Err(Refusal::new(
                "state_busy",
                "another `envcloak agents install` or `uninstall` is running",
            ));
        }
        let (state, stamp) = match read_plain(&root, Path::new(STATE_NAME), MAX_STATE) {
            Ok((bytes, stamp)) => {
                let state: State = serde_json::from_slice(&bytes).map_err(|_| {
                    Refusal::new(
                        "state_unreadable",
                        "EnvCloak's agent state file is not one this build reads",
                    )
                })?;
                if state.version != STATE_VERSION {
                    return Err(Refusal::new(
                        "state_unreadable",
                        "EnvCloak's agent state file is of another version",
                    ));
                }
                (state, Some(stamp))
            }
            Err(e) if e.kind == ScanErrorKind::NotFound => (
                State {
                    version: STATE_VERSION,
                    ..State::default()
                },
                None,
            ),
            Err(e) => return Err(Refusal::scan(e.kind)),
        };
        Ok(StateFile {
            dir: root,
            state,
            stamp,
            _lock: lock,
        })
    }

    /// Writes the state back.
    ///
    /// # Errors
    /// When it cannot be written.
    pub fn save(&mut self) -> Result<(), Refusal> {
        let mut bytes = serde_json::to_vec_pretty(&self.state).map_err(|_| {
            Refusal::new(
                "state_unwritable",
                "EnvCloak's agent state could not be written",
            )
        })?;
        bytes.push(b'\n');
        let rel = Path::new(STATE_NAME);
        let stamp = match self.stamp {
            Some(s) => replace_atomically(&self.dir, rel, &bytes, &s),
            None => create_atomically(&self.dir, rel, &bytes, 0o600),
        }
        .map_err(|e| Refusal::modify(&e))?;
        self.stamp = Some(stamp);
        Ok(())
    }
}

/// Where backups go before a change.
pub trait Backups {
    /// Backs up `bytes`, the file at `path` with permission bits `mode`,
    /// before it changes. Returns the backup's id.
    ///
    /// # Errors
    /// When the backup was not made: nothing is changed then.
    fn back_up(&mut self, path: &Path, bytes: &[u8], mode: u32) -> Result<String, Refusal>;
    /// Records `after`, what the change left, as the backup's result.
    ///
    /// # Errors
    /// When it could not be recorded.
    fn record(&mut self, id: &str, after: &[u8]) -> Result<(), Refusal>;
}

/// Backups v2 sealed by the daemon (SPEC §6.4; docs/IPC.md "Backups v2").
#[derive(Debug)]
pub struct DaemonBackups {
    client: envcloak_ipc::Client,
    claims: Vec<String>,
}

impl DaemonBackups {
    pub fn new(client: envcloak_ipc::Client, claims: Vec<String>) -> Self {
        DaemonBackups { client, claims }
    }
}

fn backup_failed(e: &envcloak_ipc::ClientError) -> Refusal {
    let f = envcloak_client::fail::Failure::from(*e);
    Refusal::new(
        "backup_failed",
        format!(
            "EnvCloak could not back the file up first ({}), so it was not changed",
            f.token()
        ),
    )
}

impl Backups for DaemonBackups {
    fn back_up(&mut self, path: &Path, bytes: &[u8], mode: u32) -> Result<String, Refusal> {
        let text = path.to_str().ok_or_else(|| {
            Refusal::new(
                "not_utf8_path",
                "the file's path is not UTF-8, which a backup cannot name",
            )
        })?;
        let begun = self
            .client
            .backup_v2_begin(&BackupBeginParams {
                purpose: "agents".to_owned(),
                files: vec![BackupPlanFile {
                    path: text.to_owned(),
                    size: bytes.len() as u64,
                    mode: mode & 0o7777,
                }],
                claims: self.claims.clone(),
            })
            .map_err(|e| backup_failed(&e))?;
        let size = usize::try_from(begun.chunk_size)
            .ok()
            .filter(|s| *s > 0)
            .unwrap_or(envcloak_core::file_backup_v2::CHUNK_V2);
        let mut chunks: Vec<&[u8]> = bytes.chunks(size).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        for (k, c) in chunks.iter().enumerate() {
            let k = u32::try_from(k)
                .map_err(|_| Refusal::new("too_large", "the file is too large to back up"))?;
            self.client
                .backup_v2_put(&begun.id, 0, k, SecretBytes::copy_from(c))
                .map_err(|e| backup_failed(&e))?;
        }
        self.client
            .backup_v2_commit(&begun.id)
            .map_err(|e| backup_failed(&e))?;
        Ok(begun.id)
    }

    fn record(&mut self, id: &str, after: &[u8]) -> Result<(), Refusal> {
        let digest: [u8; 32] = Sha256::digest(after).into();
        self.client
            .backup_v2_record_result(id, 0, &digest)
            .map(drop)
            .map_err(|e| backup_failed(&e))
    }
}

/// The hex SHA-256 of `b`.
pub fn sha256_hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(b)
        .iter()
        .fold(String::with_capacity(64), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

/// What happened to one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Already as it should be.
    Unchanged,
    /// Changed (`created` when EnvCloak made it), after the backup named.
    Changed {
        created: bool,
        backup: Option<String>,
    },
    /// Removed, after the backup named.
    Removed { backup: Option<String> },
    /// Not changed, and why.
    Refused(Refusal),
}

/// A file the installer changes.
#[derive(Debug, Clone)]
pub struct Target {
    /// Absolute.
    pub path: PathBuf,
    /// The host it is changed for, or `project`.
    pub host: &'static str,
    /// `global`, or the project directory.
    pub scope: String,
    /// The host rewrites it itself (D-16).
    pub host_owned: bool,
    /// The host's name, for messages.
    pub host_name: &'static str,
}

/// What an edit makes of a file: its new contents and the edits they
/// hold, or `None` for no change.
pub type Edited = Option<(Vec<u8>, Vec<Edit>)>;
/// An edit of a file's contents (`None` when it does not exist).
pub type EditFn<'a> = dyn FnMut(Option<&[u8]>) -> Result<Edited, Refusal> + 'a;
/// A structural undo: the current contents, the recorded edits, and
/// whether EnvCloak created the file.
pub type UndoFn<'a> = dyn FnMut(&[u8], &[Edit], bool) -> Result<Undo, Refusal> + 'a;

/// What an undo makes of a file changed since EnvCloak's last write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Undo {
    /// Nothing of EnvCloak's is in it.
    Nothing,
    /// Its new contents.
    Rewrite(Vec<u8>),
    /// Nothing is left but what EnvCloak made: remove it.
    Remove,
}

/// Changes and undoes files, keeping the record.
pub struct Writer<'a> {
    pub state: &'a mut State,
    pub backups: &'a mut dyn Backups,
    pub now: SystemTime,
}

impl std::fmt::Debug for Writer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer").finish_non_exhaustive()
    }
}

/// A file read for a change.
struct Read {
    root: ScanRoot,
    name: PathBuf,
    current: Option<(Vec<u8>, FileStamp)>,
}

fn open_target(path: &Path, create_dir: bool) -> Result<Read, Refusal> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(Refusal::new("invalid_path", "not a file's path"));
    };
    if create_dir && !parent.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|_| Refusal::new("unwritable", "its directory could not be made"))?;
    }
    let root = open_root(parent).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Refusal::scan(ScanErrorKind::NotFound),
        std::io::ErrorKind::PermissionDenied => Refusal::scan(ScanErrorKind::Unreadable),
        _ => Refusal::new("unreadable", "its directory could not be opened"),
    })?;
    let name = PathBuf::from(name);
    let current = match read_plain(&root, &name, MAX_FILE) {
        Ok((bytes, stamp)) => {
            if stamp.nlink > 1 {
                return Err(Refusal::new(
                    "hard_linked",
                    "it has another hard link, which would keep its old contents: reported, \
                     never changed",
                ));
            }
            Some((bytes, stamp))
        }
        Err(e) if e.kind == ScanErrorKind::NotFound => None,
        Err(e) => return Err(Refusal::scan(e.kind)),
    };
    Ok(Read {
        root,
        name,
        current,
    })
}

impl Writer<'_> {
    /// Whether `stamp` is the one EnvCloak recorded for `path` right after
    /// its own last write.
    fn own(&self, path: &Path, stamp: &FileStamp) -> bool {
        let k = key(path);
        let s = Stamp::from(*stamp);
        self.state.files.get(&k).is_some_and(|r| r.stamp == s)
            || self.state.written.get(&k) == Some(&s)
    }

    /// D-16: a file its host rewrites is changed only while no other
    /// process has it open, and, unless EnvCloak's own last write left it
    /// as it is, when it was not modified in the last 2 minutes.
    fn host_rule(&self, t: &Target, r: &Read, stamp: &FileStamp) -> Result<(), Refusal> {
        if !t.host_owned {
            return Ok(());
        }
        if !self.own(&t.path, stamp) && stamp.age_at(self.now).is_none_or(|a| a < MIN_AGE.as_secs())
        {
            return Err(Refusal::new(
                "recently_changed",
                format!(
                    "{} or the person changed it in the last 2 minutes: quit {} and run this \
                     again in 2 minutes",
                    t.host_name, t.host_name
                ),
            ));
        }
        let f = envcloak_sys::open_beneath(r.root.dir(), r.name.as_os_str())
            .map_err(|_| Refusal::scan(ScanErrorKind::Changed))?;
        match envcloak_sys::open_elsewhere(&f) {
            InUse::Yes => Err(Refusal::new(
                "open_elsewhere",
                format!("another program has it open: quit {} first", t.host_name),
            )),
            InUse::Unmatched => Err(Refusal::scan(ScanErrorKind::Changed)),
            InUse::No | InUse::Unknown => Ok(()),
        }
    }

    /// Changes the file `t` names to what `edit` makes of its contents
    /// (`None` when it does not exist): `Ok(None)` for no change, else the
    /// new contents and the edits they hold.
    pub fn change(&mut self, t: &Target, edit: &mut EditFn<'_>) -> Outcome {
        match self.try_change(t, edit) {
            Ok(o) => o,
            Err(r) => Outcome::Refused(r),
        }
    }

    fn try_change(&mut self, t: &Target, edit: &mut EditFn<'_>) -> Result<Outcome, Refusal> {
        let r = open_target(&t.path, true)?;
        let before = r.current.as_ref().map(|(b, _)| b.as_slice());
        let Some((after, edits)) = edit(before)? else {
            return Ok(Outcome::Unchanged);
        };
        if before == Some(after.as_slice()) {
            return Ok(Outcome::Unchanged);
        }
        let backup = match &r.current {
            Some((bytes, stamp)) => {
                self.host_rule(t, &r, stamp)?;
                Some(self.backups.back_up(&t.path, bytes, stamp.mode)?)
            }
            None => None,
        };
        let stamp = match &r.current {
            Some((_, stamp)) => replace_atomically(&r.root, &r.name, &after, stamp),
            None => create_atomically(&r.root, &r.name, &after, 0o600),
        }
        .map_err(|e| Refusal::modify(&e))?;
        if let Some(id) = &backup {
            self.backups.record(id, &after)?;
        }
        let before_text = String::from_utf8_lossy(before.unwrap_or_default()).into_owned();
        let after_text = String::from_utf8_lossy(&after).into_owned();
        let sp = splice(&before_text, &after_text);
        let k = key(&t.path);
        let created = r.current.is_none();
        self.state.written.remove(&k);
        let rec = self.state.files.entry(k).or_insert_with(|| FileRecord {
            host: t.host.to_owned(),
            scope: t.scope.clone(),
            created,
            pre_sha256: sha256_hex(before.unwrap_or_default()),
            post_sha256: String::new(),
            stamp: Stamp::from(stamp),
            splices: Vec::new(),
            edits: Vec::new(),
        });
        rec.post_sha256 = sha256_hex(&after);
        rec.stamp = Stamp::from(stamp);
        rec.splices.push(SpliceRecord {
            at: sp.at,
            old: sp.old,
            new: sp.new,
        });
        for e in edits {
            if !rec.edits.contains(&e) {
                rec.edits.push(e);
            }
        }
        Ok(Outcome::Changed { created, backup })
    }

    /// Undoes EnvCloak's changes to `path`: exactly, while the file is
    /// what EnvCloak left; by `structural` (given the current contents and
    /// the recorded edits) when it changed since. Forgets the record when
    /// done.
    pub fn undo(&mut self, t: &Target, structural: &mut UndoFn<'_>) -> Outcome {
        match self.try_undo(t, structural) {
            Ok(o) => o,
            Err(r) => Outcome::Refused(r),
        }
    }

    fn try_undo(&mut self, t: &Target, structural: &mut UndoFn<'_>) -> Result<Outcome, Refusal> {
        let k = key(&t.path);
        let Some(rec) = self.state.files.get(&k).cloned() else {
            return Ok(Outcome::Unchanged);
        };
        let r = open_target(&t.path, false)?;
        let Some((bytes, stamp)) = &r.current else {
            // Gone already: nothing of EnvCloak's is left.
            self.state.files.remove(&k);
            return Ok(Outcome::Unchanged);
        };
        let exact = if sha256_hex(bytes) == rec.post_sha256 {
            let mut text = String::from_utf8_lossy(bytes).into_owned();
            let mut ok = true;
            for s in rec.splices.iter().rev() {
                let sp = Splice {
                    at: s.at,
                    old: s.old.clone(),
                    new: s.new.clone(),
                };
                match sp.undo(&text) {
                    Some(t) => text = t,
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            (ok && sha256_hex(text.as_bytes()) == rec.pre_sha256).then_some(text.into_bytes())
        } else {
            None
        };
        let plan = match exact {
            Some(b) if rec.created && b.is_empty() => Undo::Remove,
            Some(b) => Undo::Rewrite(b),
            None => structural(bytes, &rec.edits, rec.created)?,
        };
        let outcome = match plan {
            Undo::Nothing => Outcome::Unchanged,
            Undo::Rewrite(after) if &after == bytes => Outcome::Unchanged,
            Undo::Rewrite(after) => {
                self.host_rule(t, &r, stamp)?;
                let id = self.backups.back_up(&t.path, bytes, stamp.mode)?;
                let left = replace_atomically(&r.root, &r.name, &after, stamp)
                    .map_err(|e| Refusal::modify(&e))?;
                self.state.written.insert(k.clone(), Stamp::from(left));
                self.backups.record(&id, &after)?;
                Outcome::Changed {
                    created: false,
                    backup: Some(id),
                }
            }
            Undo::Remove => {
                // A file of EnvCloak's own making: the 2 minutes run from
                // EnvCloak's own last write, which the stamp shows.
                let at = if self.own(&t.path, stamp) {
                    let mtime = SystemTime::UNIX_EPOCH
                        + Duration::from_secs(u64::try_from(stamp.mtime).unwrap_or(0));
                    self.now.max(mtime + MIN_AGE)
                } else {
                    self.now
                };
                let id = self.backups.back_up(&t.path, bytes, stamp.mode)?;
                remove_checked_at(&r.root, &r.name, stamp, at).map_err(|e| Refusal::modify(&e))?;
                self.state.written.remove(&k);
                self.backups.record(&id, b"")?;
                Outcome::Removed { backup: Some(id) }
            }
        };
        self.state.files.remove(&k);
        Ok(outcome)
    }
}

/// The state's key for a path.
pub fn key(path: &Path) -> String {
    String::from_utf8_lossy(path.as_os_str().as_bytes()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backups kept in memory, for the writer's own tests.
    #[derive(Default)]
    struct Kept {
        made: Vec<(PathBuf, Vec<u8>)>,
        results: Vec<(String, String)>,
        refuse: bool,
    }

    impl Backups for Kept {
        fn back_up(&mut self, path: &Path, bytes: &[u8], _mode: u32) -> Result<String, Refusal> {
            if self.refuse {
                return Err(Refusal::new("backup_failed", "refused for the test"));
            }
            self.made.push((path.to_path_buf(), bytes.to_vec()));
            Ok(format!("B{}", self.made.len()))
        }
        fn record(&mut self, id: &str, after: &[u8]) -> Result<(), Refusal> {
            self.results.push((id.to_owned(), sha256_hex(after)));
            Ok(())
        }
    }

    fn target(path: &Path, host_owned: bool) -> Target {
        Target {
            path: path.to_path_buf(),
            host: "claude-code",
            scope: "global".to_owned(),
            host_owned,
            host_name: "Claude Code",
        }
    }

    fn append(text: &'static str) -> impl FnMut(Option<&[u8]>) -> Result<Edited, Refusal> {
        move |b: Option<&[u8]>| {
            let mut v = b.unwrap_or_default().to_vec();
            if v.ends_with(text.as_bytes()) {
                return Ok(None);
            }
            v.extend_from_slice(text.as_bytes());
            Ok(Some((v, vec![Edit::Block])))
        }
    }

    #[test]
    fn a_change_backs_up_first_and_an_undo_gives_the_bytes_back() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("CLAUDE.md");
        std::fs::write(&p, b"# mine\n").unwrap_or_else(|e| panic!("{e}"));
        let mut state = State::default();
        let mut kept = Kept::default();
        let mut w = Writer {
            state: &mut state,
            backups: &mut kept,
            now: SystemTime::now(),
        };
        let t = target(&p, false);
        let o = w.change(&t, &mut append("added\n"));
        assert_eq!(
            o,
            Outcome::Changed {
                created: false,
                backup: Some("B1".to_owned())
            }
        );
        assert_eq!(w.change(&t, &mut append("added\n")), Outcome::Unchanged);
        let o = w.undo(&t, &mut |_, _, _| Ok(Undo::Nothing));
        assert!(matches!(o, Outcome::Changed { .. }), "{o:?}");
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"# mine\n");
        assert!(state.files.is_empty());
        assert_eq!(kept.made[0].1, b"# mine\n");
        assert_eq!(kept.results.len(), 2);
    }

    #[test]
    fn a_created_file_is_removed_by_its_undo_at_once() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("sub/hooks.json");
        let mut state = State::default();
        let mut kept = Kept::default();
        let mut w = Writer {
            state: &mut state,
            backups: &mut kept,
            now: SystemTime::now(),
        };
        let t = target(&p, true);
        assert_eq!(
            w.change(&t, &mut append("{}\n")),
            Outcome::Changed {
                created: true,
                backup: None
            }
        );
        // Right after EnvCloak's own write: no 2-minute wait.
        let o = w.undo(&t, &mut |_, _, _| Ok(Undo::Nothing));
        assert!(matches!(o, Outcome::Removed { .. }), "{o:?}");
        assert!(!p.exists());
    }

    #[test]
    fn a_host_file_changed_in_the_last_two_minutes_is_refused_and_no_backup_no_change() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("settings.json");
        std::fs::write(&p, b"{}\n").unwrap_or_else(|e| panic!("{e}"));
        let mut state = State::default();
        let mut kept = Kept::default();
        let mut w = Writer {
            state: &mut state,
            backups: &mut kept,
            now: SystemTime::now(),
        };
        let o = w.change(&target(&p, true), &mut append("x"));
        assert!(
            matches!(&o, Outcome::Refused(r) if r.name == "recently_changed"),
            "{o:?}"
        );
        assert!(kept.made.is_empty());
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"{}\n");
        // Without a backup, nothing changes either.
        let mut kept = Kept {
            refuse: true,
            ..Kept::default()
        };
        let mut w = Writer {
            state: &mut state,
            backups: &mut kept,
            now: SystemTime::now(),
        };
        let o = w.change(&target(&p, false), &mut append("x"));
        assert!(
            matches!(&o, Outcome::Refused(r) if r.name == "backup_failed"),
            "{o:?}"
        );
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"{}\n");
    }

    /// EnvCloak's own writes, its undo included, leave a stamp it knows:
    /// an install right after an uninstall needs no 2-minute wait, while a
    /// file someone else wrote since still does.
    #[test]
    fn a_change_right_after_envcloaks_own_undo_is_its_own() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("settings.json");
        std::fs::write(&p, b"{}\n").unwrap_or_else(|e| panic!("{e}"));
        let old = SystemTime::now() - Duration::from_secs(600);
        std::fs::File::options()
            .write(true)
            .open(&p)
            .and_then(|f| f.set_modified(old))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut state = State::default();
        let mut kept = Kept::default();
        let mut w = Writer {
            state: &mut state,
            backups: &mut kept,
            now: SystemTime::now(),
        };
        let t = target(&p, true);
        assert!(matches!(w.change(&t, &mut append("x")), Outcome::Changed { .. }));
        assert!(matches!(
            w.undo(&t, &mut |_, _, _| Ok(Undo::Nothing)),
            Outcome::Changed { .. }
        ));
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"{}\n");
        let o = w.change(&t, &mut append("x"));
        assert!(matches!(o, Outcome::Changed { .. }), "{o:?}");
        assert!(matches!(
            w.undo(&t, &mut |_, _, _| Ok(Undo::Nothing)),
            Outcome::Changed { .. }
        ));
        // Someone else writes it now: the 2 minutes apply again.
        std::fs::write(&p, b"{ }\n").unwrap_or_else(|e| panic!("{e}"));
        let o = w.change(&t, &mut append("x"));
        assert!(
            matches!(&o, Outcome::Refused(r) if r.name == "recently_changed"),
            "{o:?}"
        );
    }

    /// A change made by someone else between EnvCloak's read and its
    /// rename is never overwritten: the file's stamp (inode, size, mtime,
    /// ctime) is checked again at the rename.
    #[test]
    fn a_change_between_read_and_rename_is_refused() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("CLAUDE.md");
        std::fs::write(&p, b"# mine\n").unwrap_or_else(|e| panic!("{e}"));
        let mut state = State::default();
        let mut kept = Kept::default();
        let mut w = Writer {
            state: &mut state,
            backups: &mut kept,
            now: SystemTime::now(),
        };
        let theirs = p.clone();
        let mut racing = move |b: Option<&[u8]>| {
            // The person saves the file while EnvCloak is editing it.
            std::fs::write(&theirs, b"# theirs, longer\n").unwrap_or_else(|e| panic!("{e}"));
            let mut v = b.unwrap_or_default().to_vec();
            v.extend_from_slice(b"added\n");
            Ok(Some((v, vec![Edit::Block])))
        };
        let o = w.change(&target(&p, false), &mut racing);
        assert!(matches!(&o, Outcome::Refused(r) if r.name == "changed"), "{o:?}");
        assert_eq!(
            std::fs::read(&p).unwrap_or_default(),
            b"# theirs, longer\n"
        );
        assert!(state.files.is_empty());
    }

    #[test]
    fn symlinks_hard_links_and_large_files_are_refused() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let real = dir.path().join("real.json");
        std::fs::write(&real, b"{}\n").unwrap_or_else(|e| panic!("{e}"));
        let link = dir.path().join("settings.json");
        std::os::unix::fs::symlink(&real, &link).unwrap_or_else(|e| panic!("{e}"));
        let hard = dir.path().join("config.toml");
        std::fs::hard_link(&real, &hard).unwrap_or_else(|e| panic!("{e}"));
        let big = dir.path().join("CLAUDE.md");
        std::fs::write(&big, vec![b'a'; 4 * 1024 * 1024]).unwrap_or_else(|e| panic!("{e}"));
        let mut state = State::default();
        let mut kept = Kept::default();
        let mut w = Writer {
            state: &mut state,
            backups: &mut kept,
            now: SystemTime::now() + Duration::from_secs(3600),
        };
        for (p, name) in [
            (&link, "symlink"),
            (&hard, "hard_linked"),
            (&big, "too_large"),
        ] {
            let o = w.change(&target(p, false), &mut append("x"));
            assert!(
                matches!(&o, Outcome::Refused(r) if r.name == name),
                "{p:?}: {o:?}"
            );
        }
        assert!(kept.made.is_empty());
        assert_eq!(std::fs::read(&real).unwrap_or_default(), b"{}\n");
    }
}
