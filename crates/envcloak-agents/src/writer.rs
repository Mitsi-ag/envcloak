//! How the installer changes an agent's files (M2 plan M2-08, D-16;
//! lessons L-08, L-11, L-12; SPEC §6.4 "Backups" and "Modifying a file"),
//! and what it records so `agents uninstall` removes exactly what it added.
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
//! 5. The record of the change is written to EnvCloak's state file
//!    ([`State`], `<data>/agents/state.json`) before the file is, marked
//!    as an intent ([`Intent`]): a run stopped after the file changed but
//!    before its record was confirmed still owns the change, and one
//!    stopped before the file changed does not ([`Writer`]'s `settle`).
//! 6. The file is replaced in one step, and only if it is still the file
//!    read (`envcloak_scan::replace_atomically`: its stamp checked again,
//!    change time included, just before the swap); a new file is created
//!    only if its name is still free. What the write may leave beside the
//!    file under a temporary name (the new contents, the old ones swapped
//!    out) is saved with the intent, as SHA-256 digests
//!    ([`State::leftovers`]), and the next run removes such files
//!    ([`Writer::sweep`]). A failure the write reports is checked against
//!    what the file holds: holding the change, the change was made.
//! 7. The record is confirmed with the new stamp and saved; then the
//!    backup's result (the SHA-256 of what the change left) is recorded
//!    with the daemon. A failure of either, or of the write once the file
//!    changed, is reported as such ([`Outcome::Partial`]), never as a
//!    success and never as a refusal of a change that was made.
//!
//! The state keeps no text of the person's files (lesson L-12: it sits
//! outside the vault and its sealed backups, and a config can hold a
//! literal key next to what EnvCloak edits): only SHA-256 digests, stamps,
//! EnvCloak's own edits, and for each change where its inserted text went
//! ([`crate::hunks`]), with the white space it replaced.
//!
//! Undoing a file: while it is byte for byte what EnvCloak last left
//! (its SHA-256), each change's inserted text is taken out in reverse,
//! which gives back the file as it was before the first install, its
//! SHA-256 checked, or removes a file EnvCloak created. A file changed
//! since (the host rewrote it, the person edited it), or a change that
//! replaced more than white space, has EnvCloak's edits taken out by
//! structure instead (a block, an array element, a key), and everything
//! else kept; a file that is EnvCloak's whole is removed only while it is
//! exactly what EnvCloak wrote.

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
use zeroize::Zeroizing;

use crate::hunks::{self, Hunk};

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

    /// A change's failure, naming the file it left under a temporary name
    /// in `dir` when it left one (the Codex review: the name the message
    /// says is shown was dropped).
    fn modify(e: &ModifyError, dir: &Path) -> Self {
        use envcloak_scan::ModifyErrorKind as K;
        match e.kind {
            K::NotRemoved | K::AsideChanged | K::MovedAside => Refusal::new(
                e.kind.token(),
                format!(
                    "{} ({})",
                    e.kind.message(),
                    envcloak_policy::escape_for_display(&dir.join(&e.rel).display().to_string())
                ),
            ),
            _ => Refusal::new(e.kind.token(), e.kind.message()),
        }
    }
}

/// One structural edit, kept so it can be taken out of a file changed
/// since by its host or its person. Each holds EnvCloak's own values
/// only.
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
    /// there before (a boolean, `"allow"` or `"deny"`: nothing else is
    /// written over), `created` of `path`'s last keys made for it.
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

/// A change written to the state before the file is: not yet known to
/// have been made.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    /// The SHA-256 of the file before the change (`None`: there was none).
    pub before_sha256: Option<String>,
    /// The record before the change (`None`: there was none).
    pub previous: Option<Box<FileRecord>>,
}

/// What EnvCloak did to one file. No text of the file is kept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    /// The host it was done for (`claude-code`, `codex`), or `project`.
    pub host: String,
    /// `global`, or the project directory.
    pub scope: String,
    /// The host rewrites the file itself (D-16), as the change found it.
    pub host_owned: bool,
    /// EnvCloak created the file.
    pub created: bool,
    /// The SHA-256 of the file before EnvCloak's first change.
    pub pre_sha256: String,
    /// The SHA-256 of what EnvCloak's last change left.
    pub post_sha256: String,
    /// The stamp right after EnvCloak's last write, when it is known.
    pub stamp: Option<Stamp>,
    /// Where each change's inserted text went, in order, while every
    /// change can be undone exactly; `None` once one replaced more than
    /// white space, or the file changed between two of EnvCloak's.
    pub journal: Option<Vec<Vec<Hunk>>>,
    /// The edits the changes stand for.
    pub edits: Vec<Edit>,
    /// Set while the last change is written and not yet confirmed.
    pub intent: Option<Intent>,
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
    /// The MCP server entries EnvCloak is registering, by host id: saved
    /// before the host's command runs, so a run stopped after it still
    /// owns the entry (the next run finds it there and adopts it) and one
    /// stopped before it does not.
    #[serde(default)]
    pub mcp_intent: BTreeMap<String, Value>,
    /// Files EnvCloak gave back by an undo, so nothing of its own is left
    /// in them, by absolute path, with the stamp that write left: while a
    /// file's stamp is still this one, EnvCloak's next change of it (an
    /// install right after an uninstall) is its own edit, exempt from the
    /// 2-minute rule like any other (D-16).
    #[serde(default)]
    pub written: BTreeMap<String, Stamp>,
    /// What EnvCloak's writes of a file may leave beside it under
    /// EnvCloak's temporary names (`.<name>.envcloak-<new|swap|del>-<hex>
    /// .tmp`: the new contents while they are written, the old ones once
    /// swapped out, a file being removed), by the file's absolute path, as
    /// the SHA-256 digests of those contents. Saved before each write and
    /// dropped once it is done, so a run stopped in the middle, or a write
    /// that could not remove a temporary name, leaves the next run what to
    /// clean up ([`Writer::sweep`]; Codex review: a config's copy, a
    /// literal key in it included, was left behind).
    #[serde(default)]
    pub leftovers: BTreeMap<String, Vec<String>>,
}

/// The state file's format version.
pub const STATE_VERSION: u32 = 1;

/// Where the state is saved as a run goes: before each file is changed,
/// and again once it is.
pub trait Journal {
    /// Saves `state`.
    ///
    /// # Errors
    /// When it was not saved.
    fn save(&mut self, state: &State) -> Result<(), Refusal>;
}

/// EnvCloak's agent state file, held locked while an install or an
/// uninstall runs.
#[derive(Debug)]
pub struct StateFile {
    dir: ScanRoot,
    stamp: Option<FileStamp>,
    _lock: std::fs::File,
}

const STATE_NAME: &str = "state.json";
const LOCK_NAME: &str = "state.lock";

impl StateFile {
    /// Opens (creating `<data>/agents/`, 0700, when missing) and locks the
    /// state in `data_dir`, and reads it.
    ///
    /// # Errors
    /// When the directory or the state cannot be read, the state is not
    /// one this build reads, or another `agents install` or `uninstall`
    /// holds it.
    pub fn open(data_dir: &Path) -> Result<(StateFile, State), Refusal> {
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
        sweep_state_saves(&root, &dir);
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
        Ok((
            StateFile {
                dir: root,
                stamp,
                _lock: lock,
            },
            state,
        ))
    }
}

/// Removes what saves of the state stopped part way left under its
/// temporary names (`.state.json.envcloak-<new|swap|del>-<hex>.tmp`) in
/// `<data>/agents/`, EnvCloak's own directory (0700), while the state's
/// lock is held: no other program writes there, and the state holds no
/// text of the person's files. A regular file of this user with no other
/// link goes; anything else stays.
fn sweep_state_saves(root: &ScanRoot, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let now = SystemTime::now();
    for e in entries.flatten() {
        let n = e.file_name();
        if temp_of(OsStr::new(STATE_NAME), &n).is_none() {
            continue;
        }
        let rel = Path::new(&n);
        let Ok((bytes, stamp)) = read_plain(root, rel, MAX_STATE) else {
            continue;
        };
        drop(Zeroizing::new(bytes));
        if stamp.nlink != 1 {
            continue;
        }
        let mtime =
            SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(stamp.mtime).unwrap_or(0));
        let _ = remove_checked_at(root, rel, &stamp, now.max(mtime + MIN_AGE));
    }
}

impl Journal for StateFile {
    fn save(&mut self, state: &State) -> Result<(), Refusal> {
        let unwritable = || {
            Refusal::new(
                "state_unwritable",
                "EnvCloak's agent state could not be written",
            )
        };
        let mut bytes = serde_json::to_vec_pretty(state).map_err(|_| unwritable())?;
        bytes.push(b'\n');
        let rel = Path::new(STATE_NAME);
        let stamp = match self.stamp {
            Some(s) => replace_atomically(&self.dir, rel, &bytes, &s),
            None => create_atomically(&self.dir, rel, &bytes, 0o600),
        }
        .map_err(|_| unwritable())?;
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
            .map_err(|e| {
                let f = envcloak_client::fail::Failure::from(e);
                Refusal::new(
                    "result_unrecorded",
                    format!(
                        "the file was changed, but EnvCloak could not record what the change \
                         left with its backup ({}): the backup restores only with --unrecorded",
                        f.token()
                    ),
                )
            })
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

/// What was done to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Made {
    Created,
    Changed,
    Removed,
}

impl Made {
    /// The word a report uses.
    pub fn word(self) -> &'static str {
        match self {
            Made::Created => "created",
            Made::Changed => "changed",
            Made::Removed => "removed",
        }
    }
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
    /// The file was changed (`made`), after the backup named, but a step
    /// after the change failed (`failed`): the run is incomplete.
    Partial {
        made: Made,
        backup: Option<String>,
        failed: Refusal,
    },
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
/// An edit of a file's contents (`None` when it does not exist), given
/// EnvCloak's record of the file, if it has one.
pub type EditFn<'a> = dyn FnMut(Option<&[u8]>, Option<&FileRecord>) -> Result<Edited, Refusal> + 'a;
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
    pub journal: &'a mut dyn Journal,
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

/// The steps after a change that can fail once the file has changed.
fn finished(made: Made, backup: Option<String>, failed: Option<Refusal>) -> Outcome {
    match (failed, made) {
        (Some(failed), made) => Outcome::Partial {
            made,
            backup,
            failed,
        },
        (None, Made::Removed) => Outcome::Removed { backup },
        (None, made) => Outcome::Changed {
            created: made == Made::Created,
            backup,
        },
    }
}

impl Writer<'_> {
    /// Whether `stamp` is the one EnvCloak recorded for `path` right after
    /// its own last write.
    fn own(&self, path: &Path, stamp: &FileStamp) -> bool {
        let k = key(path);
        let s = Stamp::from(*stamp);
        self.state.files.get(&k).is_some_and(|r| r.stamp == Some(s))
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

    /// Settles a change whose record was written and not confirmed (a run
    /// stopped between the two), by what the file holds now: the change
    /// was made (the record stands, its stamp unknown, so the 2 minutes
    /// apply), was not (the record before it comes back), or the file
    /// changed since (the record stands, undone by structure only).
    fn settle(&mut self, k: &str, current: Option<&[u8]>) {
        let Some(rec) = self.state.files.get_mut(k) else {
            return;
        };
        let Some(intent) = rec.intent.take() else {
            return;
        };
        let now = current.map(sha256_hex);
        if now.as_deref() == Some(rec.post_sha256.as_str()) {
            rec.stamp = None;
        } else if now == intent.before_sha256 {
            match intent.previous {
                Some(p) => {
                    self.state.files.insert(k.to_owned(), *p);
                }
                None => {
                    self.state.files.remove(k);
                }
            }
        } else {
            rec.stamp = None;
            rec.journal = None;
        }
    }

    /// Changes the file `t` names to what `edit` makes of its contents
    /// (`None` when it does not exist) and EnvCloak's record of it:
    /// `Ok(None)` for no change, else the new contents and the edits they
    /// hold.
    pub fn change(&mut self, t: &Target, edit: &mut EditFn<'_>) -> Outcome {
        match self.try_change(t, edit) {
            Ok(o) => o,
            Err(r) => Outcome::Refused(r),
        }
    }

    /// The backup made for a change that did not happen gets the file as
    /// it is as its result, so its restore statement is true.
    fn not_made(&mut self, backup: Option<&str>, bytes: &[u8]) {
        if let Some(id) = backup {
            let _ = self.backups.record(id, bytes);
        }
    }

    fn try_change(&mut self, t: &Target, edit: &mut EditFn<'_>) -> Result<Outcome, Refusal> {
        let r = open_target(&t.path, true)?;
        let k = key(&t.path);
        let before = r.current.as_ref().map(|(b, _)| b.as_slice());
        self.settle(&k, before);
        let prev = self.state.files.get(&k).cloned();
        let edited = edit(before, prev.as_ref());
        // What earlier writes of the file left beside it goes first, now
        // that what this one would write is known: a write stopped part
        // way left the first bytes of these same contents (Codex review).
        let staged = match &edited {
            Ok(Some((a, _))) => Some(a.as_slice()),
            _ => None,
        };
        let refs: Vec<&[u8]> = before.into_iter().chain(staged).collect();
        self.sweep(&t.path, &refs);
        let Some((after, edits)) = edited? else {
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
        let before_bytes = before.unwrap_or_default();
        let before_sha = sha256_hex(before_bytes);
        let created = r.current.is_none();
        let mut rec = prev.clone().unwrap_or_else(|| FileRecord {
            host: t.host.to_owned(),
            scope: t.scope.clone(),
            host_owned: t.host_owned,
            created,
            pre_sha256: before_sha.clone(),
            post_sha256: before_sha.clone(),
            stamp: None,
            journal: Some(Vec::new()),
            edits: Vec::new(),
            intent: None,
        });
        rec.host_owned |= t.host_owned;
        // The journal holds only while each change starts from what the
        // last one left.
        let chained = rec.post_sha256 == before_sha;
        rec.journal = match (rec.journal.take(), hunks::hunks(before_bytes, &after)) {
            (Some(mut j), Some(h)) if chained => {
                j.push(h);
                Some(j)
            }
            _ => None,
        };
        rec.post_sha256 = sha256_hex(&after);
        rec.stamp = None;
        for e in edits {
            if !rec.edits.contains(&e) {
                rec.edits.push(e);
            }
        }
        rec.intent = Some(Intent {
            before_sha256: r.current.as_ref().map(|_| before_sha.clone()),
            previous: prev.clone().map(Box::new),
        });
        self.state.files.insert(k.clone(), rec);
        // What the write may leave under a temporary name: the new
        // contents while they are written, the old ones once swapped out.
        let left_before = self.state.leftovers.get(&k).cloned();
        let mut digests = vec![sha256_hex(&after)];
        if r.current.is_some() {
            digests.push(before_sha.clone());
        }
        self.expect_leftovers(&k, &digests);
        if let Err(e) = self.journal.save(self.state) {
            self.restore(&k, prev);
            self.set_leftovers(&k, left_before);
            self.not_made(backup.as_deref(), before_bytes);
            return Err(e);
        }
        let done = match &r.current {
            Some((_, stamp)) => replace_file(&r.root, &r.name, &after, stamp),
            None => create_file(&r.root, &r.name, &after, 0o600),
        };
        let (stamp, mut failed) = match done {
            Ok(s) => {
                self.set_leftovers(&k, left_before);
                (Some(Stamp::from(s)), None)
            }
            Err(e) => {
                let why = Refusal::modify(&e, &dir_of(&t.path));
                if !holds(&r, &after) {
                    // Not made: the record before it comes back.
                    self.restore(&k, prev);
                    let _ = self.journal.save(self.state);
                    self.not_made(backup.as_deref(), before_bytes);
                    return Err(why);
                }
                // The file holds the change, and a step after it failed
                // (the old file left under a temporary name, a sync): the
                // change is EnvCloak's, its stamp unknown, and the outcome
                // says so (Codex review: answered as a refusal before).
                (None, Some(why))
            }
        };
        if let Some(rec) = self.state.files.get_mut(&k) {
            rec.stamp = stamp;
            rec.intent = None;
        }
        self.state.written.remove(&k);
        if let Err(e) = self.journal.save(self.state) {
            failed.get_or_insert(e);
        }
        if let Some(id) = &backup {
            if let Err(e) = self.backups.record(id, &after) {
                failed.get_or_insert(e);
            }
        }
        let made = if created {
            Made::Created
        } else {
            Made::Changed
        };
        Ok(finished(made, backup, failed))
    }

    /// Adds `digests` to what writes of the file keyed `k` may leave.
    fn expect_leftovers(&mut self, k: &str, digests: &[String]) {
        let list = self.state.leftovers.entry(k.to_owned()).or_default();
        for d in digests {
            if !list.contains(d) {
                list.push(d.clone());
            }
        }
    }

    /// Puts back what writes of the file keyed `k` may leave, as it was.
    fn set_leftovers(&mut self, k: &str, was: Option<Vec<String>>) {
        match was {
            Some(v) => {
                self.state.leftovers.insert(k.to_owned(), v);
            }
            None => {
                self.state.leftovers.remove(k);
            }
        }
    }

    /// Removes what EnvCloak's earlier writes of `path` left beside it
    /// under its temporary names ([`State::leftovers`]), given `refs`,
    /// contents of the file EnvCloak is writing or wrote (the file as it
    /// is, what this run would write): a regular file of this user of that
    /// shape, with no other link, that holds exactly contents of a recorded
    /// digest (a whole copy: new contents, old ones swapped out, a file
    /// being removed); or, under a name new contents are written under,
    /// the first bytes of contents of a recorded digest, nothing at all
    /// included (a write stopped part way: Codex review, such a copy can
    /// already hold a literal key, and was left and forgotten). Those
    /// contents are among `refs`, since the state keeps no text of the file
    /// (lesson L-12). Anything else of that shape is not shown to be
    /// EnvCloak's and stays, and so does the record, so the file goes on
    /// being reported ([`Writer::leftovers_present`]) until it is gone.
    pub fn sweep(&mut self, path: &Path, refs: &[&[u8]]) {
        let k = key(path);
        let Some(digests) = self.state.leftovers.get(&k).cloned() else {
            return;
        };
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return;
        };
        let (Ok(root), Ok(entries)) = (open_root(parent), std::fs::read_dir(parent)) else {
            return;
        };
        // The contents a part may be of: those whose digest is recorded.
        let whole: Vec<&[u8]> = refs
            .iter()
            .copied()
            .filter(|r| digests.contains(&sha256_hex(r)))
            .collect();
        let mut kept = false;
        for entry in entries.flatten() {
            let n = entry.file_name();
            let Some(shape) = temp_of(name, &n) else {
                continue;
            };
            let rel = Path::new(&n);
            let Ok((bytes, stamp)) = read_plain(&root, rel, MAX_FILE) else {
                // Not a regular file of this user that can be read: it is
                // not shown to be EnvCloak's.
                kept = true;
                continue;
            };
            let bytes = Zeroizing::new(bytes);
            let copy = digests.contains(&sha256_hex(&bytes));
            let part = shape == TempShape::New && whole.iter().any(|w| w.starts_with(&bytes));
            if stamp.nlink != 1 || !(copy || part || shape == TempShape::New && bytes.is_empty()) {
                kept = true;
                continue;
            }
            // EnvCloak's own file: the 2 minutes run from its own write.
            let mtime = SystemTime::UNIX_EPOCH
                + Duration::from_secs(u64::try_from(stamp.mtime).unwrap_or(0));
            if remove_checked_at(&root, rel, &stamp, self.now.max(mtime + MIN_AGE)).is_err() {
                kept = true;
            }
        }
        if !kept {
            self.state.leftovers.remove(&k);
        }
    }

    /// [`Writer::sweep`] for every file the state names leftovers for,
    /// each with its contents as they are.
    pub fn sweep_all(&mut self) {
        let keys: Vec<String> = self.state.leftovers.keys().cloned().collect();
        for k in keys {
            let path = PathBuf::from(&k);
            let current: Option<Zeroizing<Vec<u8>>> = open_target(&path, false)
                .ok()
                .and_then(|r| r.current)
                .map(|(b, _)| Zeroizing::new(b));
            let refs: Vec<&[u8]> = current.iter().map(|b| b.as_slice()).collect();
            self.sweep(&path, &refs);
        }
    }

    /// The files under EnvCloak's temporary names still beside the files
    /// the state names leftovers for: what a sweep could not show to be
    /// EnvCloak's, or could not remove. Each may hold a copy of part of
    /// the file, so a report names it (lesson L-08).
    pub fn leftovers_present(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for k in self.state.leftovers.keys() {
            let path = Path::new(k);
            let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                continue;
            };
            let Ok(entries) = std::fs::read_dir(parent) else {
                continue;
            };
            for e in entries.flatten() {
                if temp_of(name, &e.file_name()).is_some() {
                    out.push(parent.join(e.file_name()));
                }
            }
        }
        out.sort();
        out
    }

    /// Puts back the record a change replaced.
    fn restore(&mut self, k: &str, prev: Option<FileRecord>) {
        match prev {
            Some(p) => {
                self.state.files.insert(k.to_owned(), p);
            }
            None => {
                self.state.files.remove(k);
            }
        }
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

    /// The file as it was before EnvCloak's first change, when `bytes` is
    /// what its last one left and every change can be undone exactly.
    fn exact(rec: &FileRecord, bytes: &[u8]) -> Option<Vec<u8>> {
        if sha256_hex(bytes) != rec.post_sha256 {
            return None;
        }
        let mut text = bytes.to_vec();
        for h in rec.journal.as_ref()?.iter().rev() {
            text = hunks::unapply(&text, h)?;
        }
        (sha256_hex(&text) == rec.pre_sha256).then_some(text)
    }

    fn try_undo(&mut self, t: &Target, structural: &mut UndoFn<'_>) -> Result<Outcome, Refusal> {
        let k = key(&t.path);
        if !self.state.files.contains_key(&k) {
            return Ok(Outcome::Unchanged);
        }
        let r = open_target(&t.path, false)?;
        self.settle(&k, r.current.as_ref().map(|(b, _)| b.as_slice()));
        let Some(rec) = self.state.files.get(&k).cloned() else {
            return Ok(Outcome::Unchanged);
        };
        let Some((bytes, stamp)) = &r.current else {
            // Gone already: nothing of EnvCloak's is left.
            self.sweep(&t.path, &[]);
            self.state.files.remove(&k);
            let _ = self.journal.save(self.state);
            return Ok(Outcome::Unchanged);
        };
        let ours = sha256_hex(bytes) == rec.post_sha256;
        let plan = match Self::exact(&rec, bytes) {
            Some(b) if rec.created && b.is_empty() => Ok(Undo::Remove),
            Some(b) => Ok(Undo::Rewrite(b)),
            // EnvCloak's whole file, exactly as it wrote it.
            None if ours && rec.created && rec.edits.contains(&Edit::WholeFile) => Ok(Undo::Remove),
            None => structural(bytes, &rec.edits, rec.created),
        };
        // What earlier writes left beside it goes first, now that what
        // this one would write is known (a stopped write left its first
        // bytes).
        let staged = match &plan {
            Ok(Undo::Rewrite(a)) => Some(a.as_slice()),
            _ => None,
        };
        let refs: Vec<&[u8]> = std::iter::once(bytes.as_slice()).chain(staged).collect();
        self.sweep(&t.path, &refs);
        let plan = plan?;
        let t = Target {
            host_owned: t.host_owned || rec.host_owned,
            ..t.clone()
        };
        let dir = dir_of(&t.path);
        match plan {
            Undo::Nothing => {
                self.state.files.remove(&k);
                let _ = self.journal.save(self.state);
                Ok(Outcome::Unchanged)
            }
            Undo::Rewrite(after) if &after == bytes => {
                self.state.files.remove(&k);
                let _ = self.journal.save(self.state);
                Ok(Outcome::Unchanged)
            }
            Undo::Rewrite(after) => {
                self.host_rule(&t, &r, stamp)?;
                let id = self.backups.back_up(&t.path, bytes, stamp.mode)?;
                let left_before = self.state.leftovers.get(&k).cloned();
                self.expect_leftovers(&k, &[sha256_hex(bytes), sha256_hex(&after)]);
                if let Err(e) = self.journal.save(self.state) {
                    self.set_leftovers(&k, left_before);
                    self.not_made(Some(&id), bytes);
                    return Err(e);
                }
                let mut failed = None;
                match replace_file(&r.root, &r.name, &after, stamp) {
                    Ok(left) => {
                        self.state.written.insert(k.clone(), Stamp::from(left));
                        self.set_leftovers(&k, left_before);
                    }
                    Err(e) => {
                        let why = Refusal::modify(&e, &dir);
                        if !holds(&r, &after) {
                            let _ = self.journal.save(self.state);
                            self.not_made(Some(&id), bytes);
                            return Err(why);
                        }
                        // Undone, and a step after it failed: said so.
                        self.state.written.remove(&k);
                        failed = Some(why);
                    }
                }
                self.state.files.remove(&k);
                if let Err(e) = self.journal.save(self.state) {
                    failed.get_or_insert(e);
                }
                if let Err(e) = self.backups.record(&id, &after) {
                    failed.get_or_insert(e);
                }
                Ok(finished(Made::Changed, Some(id), failed))
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
                let left_before = self.state.leftovers.get(&k).cloned();
                self.expect_leftovers(&k, &[sha256_hex(bytes)]);
                if let Err(e) = self.journal.save(self.state) {
                    self.set_leftovers(&k, left_before);
                    self.not_made(Some(&id), bytes);
                    return Err(e);
                }
                let mut failed = None;
                match remove_file(&r.root, &r.name, stamp, at) {
                    Ok(()) => self.set_leftovers(&k, left_before),
                    Err(e) => {
                        let why = Refusal::modify(&e, &dir);
                        if present(&r) {
                            let _ = self.journal.save(self.state);
                            self.not_made(Some(&id), bytes);
                            return Err(why);
                        }
                        // Gone from its name, and a step after it failed
                        // (the file left under a temporary name): said so.
                        failed = Some(why);
                    }
                }
                self.state.files.remove(&k);
                self.state.written.remove(&k);
                if let Err(e) = self.journal.save(self.state) {
                    failed.get_or_insert(e);
                }
                if let Err(e) = self.backups.record(&id, b"") {
                    failed.get_or_insert(e);
                }
                Ok(finished(Made::Removed, Some(id), failed))
            }
        }
    }
}

/// The directory a target's temporary names are in, for messages.
fn dir_of(path: &Path) -> PathBuf {
    path.parent().map(Path::to_path_buf).unwrap_or_default()
}

/// Whether the file `r` read now holds exactly `want` (a change that
/// reported a failure may have been made: what the file holds says).
fn holds(r: &Read, want: &[u8]) -> bool {
    read_plain(&r.root, &r.name, want.len().max(MAX_FILE))
        .is_ok_and(|(b, _)| *Zeroizing::new(b) == want)
}

/// Whether a file has the name `r` read.
fn present(r: &Read) -> bool {
    !matches!(
        read_plain(&r.root, &r.name, MAX_FILE),
        Err(e) if e.kind == ScanErrorKind::NotFound
    )
}

/// What a temporary name holds while a file changes: new contents being
/// written (`new`, the one a stopped write may leave in part), or a whole
/// file moved there (`swap`, `del`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TempShape {
    New,
    Moved,
}

/// The shape of `n` when it is a temporary name EnvCloak's atomic writes
/// give a file named `name` while it changes (`envcloak_scan`'s
/// `temp_name`: `.<name>.envcloak-<new|swap|del>-<16 hex>.tmp`, the name
/// left out when it is longer than 128 bytes); `None` otherwise.
fn temp_of(name: &OsStr, n: &OsStr) -> Option<TempShape> {
    let n = n.as_bytes();
    let name = name.as_bytes();
    let rest = n.strip_prefix(b".")?;
    let rest = if name.len() <= 128 {
        rest.strip_prefix(name)?
    } else {
        rest
    };
    let rest = rest.strip_prefix(b".envcloak-")?;
    let (shape, hex) = [
        (&b"new-"[..], TempShape::New),
        (b"swap-", TempShape::Moved),
        (b"del-", TempShape::Moved),
    ]
    .iter()
    .find_map(|(w, shape)| Some((*shape, rest.strip_prefix(*w)?.strip_suffix(b".tmp")?)))?;
    (hex.len() == 16 && hex.iter().all(u8::is_ascii_hexdigit)).then_some(shape)
}

/// A failure a unit test puts in a file operation: after it was done, or
/// instead of it.
#[cfg(test)]
pub(crate) enum Inject {
    After(ModifyError),
    Instead(ModifyError),
}

#[cfg(test)]
thread_local! {
    pub(crate) static INJECT: std::cell::RefCell<Option<Inject>> =
        const { std::cell::RefCell::new(None) };
}

/// The operation with a unit test's failure in it, if one was put there.
fn injected<T>(op: impl FnOnce() -> Result<T, ModifyError>) -> Result<T, ModifyError> {
    #[cfg(test)]
    if let Some(i) = INJECT.with(|c| c.borrow_mut().take()) {
        return match i {
            Inject::Instead(e) => Err(e),
            Inject::After(e) => op().and(Err(e)),
        };
    }
    op()
}

fn replace_file(
    root: &ScanRoot,
    name: &Path,
    new: &[u8],
    expect: &FileStamp,
) -> Result<FileStamp, ModifyError> {
    injected(|| replace_atomically(root, name, new, expect))
}

fn create_file(
    root: &ScanRoot,
    name: &Path,
    new: &[u8],
    mode: u32,
) -> Result<FileStamp, ModifyError> {
    injected(|| create_atomically(root, name, new, mode))
}

fn remove_file(
    root: &ScanRoot,
    name: &Path,
    expect: &FileStamp,
    at: SystemTime,
) -> Result<(), ModifyError> {
    injected(|| remove_checked_at(root, name, expect, at))
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
        refuse_record: bool,
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
            if self.refuse_record {
                return Err(Refusal::new("result_unrecorded", "refused for the test"));
            }
            self.results.push((id.to_owned(), sha256_hex(after)));
            Ok(())
        }
    }

    /// The state as saved, each save kept; `fail` refuses the saves whose
    /// numbers (from 1) it holds.
    #[derive(Default)]
    struct Saved {
        saves: Vec<State>,
        fail: Vec<usize>,
        count: usize,
    }

    impl Journal for Saved {
        fn save(&mut self, state: &State) -> Result<(), Refusal> {
            self.count += 1;
            if self.fail.contains(&self.count) {
                return Err(Refusal::new("state_unwritable", "refused for the test"));
            }
            self.saves.push(state.clone());
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

    fn append(
        text: &'static str,
    ) -> impl FnMut(Option<&[u8]>, Option<&FileRecord>) -> Result<Edited, Refusal> {
        move |b: Option<&[u8]>, _| {
            let mut v = b.unwrap_or_default().to_vec();
            if v.ends_with(text.as_bytes()) {
                return Ok(None);
            }
            v.extend_from_slice(text.as_bytes());
            Ok(Some((v, vec![Edit::Block])))
        }
    }

    fn nothing(_: &[u8], _: &[Edit], _: bool) -> Result<Undo, Refusal> {
        Ok(Undo::Nothing)
    }

    macro_rules! writer {
        ($state:expr, $saved:expr, $kept:expr) => {
            Writer {
                state: $state,
                journal: $saved,
                backups: $kept,
                now: SystemTime::now(),
            }
        };
    }

    #[test]
    fn a_change_backs_up_first_and_an_undo_gives_the_bytes_back() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("CLAUDE.md");
        std::fs::write(&p, b"# mine").unwrap_or_else(|e| panic!("{e}"));
        let (mut state, mut saved, mut kept) =
            (State::default(), Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let t = target(&p, false);
        let o = w.change(&t, &mut append("\n\nadded\n"));
        assert_eq!(
            o,
            Outcome::Changed {
                created: false,
                backup: Some("B1".to_owned())
            }
        );
        assert_eq!(w.change(&t, &mut append("\n\nadded\n")), Outcome::Unchanged);
        let o = w.undo(&t, &mut nothing);
        assert!(matches!(o, Outcome::Changed { .. }), "{o:?}");
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"# mine");
        assert!(state.files.is_empty());
        assert_eq!(kept.made[0].1, b"# mine");
        assert_eq!(kept.results.len(), 2);
    }

    #[test]
    fn a_created_file_is_removed_by_its_undo_at_once() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("sub/hooks.json");
        let (mut state, mut saved, mut kept) =
            (State::default(), Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let t = target(&p, true);
        assert_eq!(
            w.change(&t, &mut append("{}\n")),
            Outcome::Changed {
                created: true,
                backup: None
            }
        );
        // Right after EnvCloak's own write: no 2-minute wait.
        let o = w.undo(&t, &mut nothing);
        assert!(matches!(o, Outcome::Removed { .. }), "{o:?}");
        assert!(!p.exists());
    }

    #[test]
    fn a_host_file_changed_in_the_last_two_minutes_is_refused_and_no_backup_no_change() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("settings.json");
        std::fs::write(&p, b"{}\n").unwrap_or_else(|e| panic!("{e}"));
        let (mut state, mut saved, mut kept) =
            (State::default(), Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);
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
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let o = w.change(&target(&p, false), &mut append("x"));
        assert!(
            matches!(&o, Outcome::Refused(r) if r.name == "backup_failed"),
            "{o:?}"
        );
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"{}\n");
        assert!(state.files.is_empty());
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
        let (mut state, mut saved, mut kept) =
            (State::default(), Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let t = target(&p, true);
        assert!(matches!(
            w.change(&t, &mut append("x")),
            Outcome::Changed { .. }
        ));
        assert!(matches!(w.undo(&t, &mut nothing), Outcome::Changed { .. }));
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"{}\n");
        let o = w.change(&t, &mut append("x"));
        assert!(matches!(o, Outcome::Changed { .. }), "{o:?}");
        assert!(matches!(w.undo(&t, &mut nothing), Outcome::Changed { .. }));
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
        let (mut state, mut saved, mut kept) =
            (State::default(), Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let theirs = p.clone();
        let mut racing = move |b: Option<&[u8]>, _: Option<&FileRecord>| {
            // The person saves the file while EnvCloak is editing it.
            std::fs::write(&theirs, b"# theirs, longer\n").unwrap_or_else(|e| panic!("{e}"));
            let mut v = b.unwrap_or_default().to_vec();
            v.extend_from_slice(b"added\n");
            Ok(Some((v, vec![Edit::Block])))
        };
        let o = w.change(&target(&p, false), &mut racing);
        assert!(
            matches!(&o, Outcome::Refused(r) if r.name == "changed"),
            "{o:?}"
        );
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"# theirs, longer\n");
        assert!(state.files.is_empty());
        // The backup's result says the file was left as it was read.
        assert_eq!(kept.results, [("B1".to_owned(), sha256_hex(b"# mine\n"))]);
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
        let (mut state, mut saved, mut kept) =
            (State::default(), Saved::default(), Kept::default());
        let mut w = Writer {
            state: &mut state,
            journal: &mut saved,
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

    /// Lesson L-12: what the state keeps of a change is where EnvCloak's
    /// text went, never the person's own text, even text between two
    /// places one change edits.
    ///
    /// Mutation checked: the journal kept as one splice of the whole span
    /// between the first and last changed byte, with its old text (the
    /// previous `SpliceRecord { at, old, new }`): the canary between the
    /// two edits is in the saved state and this fails.
    #[test]
    fn the_state_keeps_no_text_of_the_file() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("settings.json");
        let canary = format!("canary{:016x}", u64::from(std::process::id()) << 7 | 0x5a5a);
        let before = format!(
            "{{\n  \"deny\": [\n    \"A\"\n  ],\n  \"env\": {{\n    \"KEY\": \"{canary}\"\n  \
             }},\n  \"z\": 1\n}}\n"
        );
        std::fs::write(&p, &before).unwrap_or_else(|e| panic!("{e}"));
        let (mut state, mut saved, mut kept) =
            (State::default(), Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let t = target(&p, false);
        let two_sites = |b: Option<&[u8]>, _: Option<&FileRecord>| {
            let text = String::from_utf8(b.unwrap_or_default().to_vec()).unwrap_or_default();
            if text.contains("\"B\"") {
                return Ok(None);
            }
            let text = text.replacen("\"A\"\n", "\"A\",\n    \"B\"\n", 1).replacen(
                "\"z\": 1\n",
                "\"z\": 1,\n  \"hooks\": {}\n",
                1,
            );
            Ok(Some((text.into_bytes(), vec![Edit::Block])))
        };
        let mut edit = two_sites;
        assert!(matches!(w.change(&t, &mut edit), Outcome::Changed { .. }));
        for s in std::iter::once(&state).chain(saved.saves.iter()) {
            let kept = serde_json::to_string(s).unwrap_or_default();
            assert!(!kept.contains(&canary), "the state holds the file's text");
            assert!(!kept.contains("\"B\""), "the state holds the inserted text");
        }
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        assert!(matches!(w.undo(&t, &mut nothing), Outcome::Changed { .. }));
        assert_eq!(
            std::fs::read_to_string(&p).unwrap_or_default(),
            before,
            "the exact undo"
        );
    }

    /// Lesson L-08 and the state's write-ahead record: a run that stops
    /// after the file changed still owns the change, one that stops
    /// before does not, and a step that fails after the change says the
    /// file was changed.
    ///
    /// Mutations checked: the record saved only after the rename (the
    /// first save moved below `replace_atomically`): the stopped run's
    /// change is not in the saved state and this fails. A failed result
    /// record answered as a refusal (`Outcome::Refused` for the
    /// `record` error): the outcome is not `Partial` and this fails.
    #[test]
    fn a_change_is_recorded_before_it_is_made_and_failures_after_it_say_so() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("CLAUDE.md");
        std::fs::write(&p, b"# mine\n").unwrap_or_else(|e| panic!("{e}"));
        let t = target(&p, false);

        // The save after the change fails (the run is stopped there): the
        // first save already holds the change, as an intent.
        let (mut state, mut kept) = (State::default(), Kept::default());
        let mut saved = Saved {
            fail: vec![2],
            ..Saved::default()
        };
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let o = w.change(&t, &mut append("added\n"));
        assert!(
            matches!(&o, Outcome::Partial { made: Made::Changed, failed, .. } if failed.name == "state_unwritable"),
            "{o:?}"
        );
        let on_disk = saved.saves.last().cloned().unwrap_or_default();
        let rec = on_disk.files.get(&key(&p)).cloned();
        assert!(rec.as_ref().is_some_and(|r| r.intent.is_some()), "{rec:?}");
        // The next run, from what was saved, settles it as made and owns
        // it: the uninstall takes the block out.
        let mut state = on_disk;
        let (mut saved, mut kept) = (Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let o = w.undo(&t, &mut nothing);
        assert!(matches!(o, Outcome::Changed { .. }), "{o:?}");
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"# mine\n");

        // A run stopped after the record was saved and before the file
        // changed (here the directory refuses the new file): the next run
        // drops the intent, and the file is the person's alone.
        use std::os::unix::fs::PermissionsExt as _;
        let sub = dir.path().join("ro");
        std::fs::create_dir(&sub).unwrap_or_else(|e| panic!("{e}"));
        let q = sub.join("AGENTS.md");
        std::fs::write(&q, b"# theirs\n").unwrap_or_else(|e| panic!("{e}"));
        let mode = |m: u32| {
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(m))
                .unwrap_or_else(|e| panic!("{e}"));
        };
        mode(0o500);
        // As root the directory's mode stops nothing: this part needs a
        // user it stops.
        let probe = sub.join("probe");
        if std::fs::write(&probe, b"").is_ok() {
            mode(0o700);
            return;
        }
        let tq = target(&q, false);
        let (mut state, mut saved, mut kept) =
            (State::default(), Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let o = w.change(&tq, &mut append("added\n"));
        mode(0o700);
        assert!(matches!(o, Outcome::Refused(_)), "{o:?}");
        assert!(state.files.is_empty());
        let first = saved.saves.first().cloned().unwrap_or_default();
        assert!(
            first
                .files
                .get(&key(&q))
                .is_some_and(|r| r.intent.is_some())
        );
        let mut state = first;
        let (mut saved, mut kept) = (Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let o = w.undo(&tq, &mut |_, _, _| {
            Ok(Undo::Rewrite(b"not EnvCloak's to write\n".to_vec()))
        });
        assert_eq!(o, Outcome::Unchanged);
        assert!(state.files.is_empty());
        assert_eq!(std::fs::read(&q).unwrap_or_default(), b"# theirs\n");

        // The backup's result cannot be recorded: the file was changed,
        // and the outcome says so, with the record kept.
        std::fs::write(&p, b"# mine\n").unwrap_or_else(|e| panic!("{e}"));
        let (mut state, mut saved) = (State::default(), Saved::default());
        let mut kept = Kept {
            refuse_record: true,
            ..Kept::default()
        };
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let o = w.change(&t, &mut append("added\n"));
        assert!(
            matches!(&o, Outcome::Partial { made: Made::Changed, failed, .. } if failed.name == "result_unrecorded"),
            "{o:?}"
        );
        assert!(
            state
                .files
                .get(&key(&p))
                .is_some_and(|r| r.intent.is_none())
        );
    }

    /// The leftover name `replace_atomically` gives `name`, with `hex`.
    fn temp(dir: &Path, name: &str, what: &str, hex: &str) -> PathBuf {
        dir.join(format!(".{name}.envcloak-{what}-{hex}.tmp"))
    }

    fn not_removed(rel: &Path) -> ModifyError {
        ModifyError {
            rel: rel.to_path_buf(),
            kind: envcloak_scan::ModifyErrorKind::NotRemoved,
        }
    }

    /// The Codex review: a failure that the file system reports after the
    /// change was made (the old file left under a temporary name, a sync)
    /// was reported as a refusal, and EnvCloak dropped its record of a
    /// change that was in the file. What the file holds now says whether
    /// the change was made: made, it is EnvCloak's, and the outcome is
    /// the change with the failure, naming the file left behind; not
    /// made, the record before it comes back. The same for an undo's
    /// rewrite and removal.
    ///
    /// Mutation checked: every failure of the file operation answered as
    /// a refusal (the previous `self.restore(&k, prev)` and `return
    /// Err(Refusal::modify(&e))`, without `holds`): the made changes are
    /// `Refused` and their records gone, and this fails.
    #[test]
    fn a_failure_after_the_change_is_reported_as_the_change() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("CLAUDE.md");
        std::fs::write(&p, b"# mine\n").unwrap_or_else(|e| panic!("{e}"));
        let t = target(&p, false);
        let (mut state, mut saved, mut kept) =
            (State::default(), Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);

        // The swap was made, and the old file could not be unlinked: it is
        // under a temporary name, which the outcome names.
        let left = temp(dir.path(), "CLAUDE.md", "swap", "00000000000000a1");
        std::fs::write(&left, b"# mine\n").unwrap_or_else(|e| panic!("{e}"));
        INJECT.with(|c| {
            *c.borrow_mut() = Some(Inject::After(not_removed(Path::new(
                left.file_name().unwrap_or_default(),
            ))));
        });
        let o = w.change(&t, &mut append("added\n"));
        match &o {
            Outcome::Partial {
                made: Made::Changed,
                failed,
                backup: Some(_),
            } => {
                assert_eq!(failed.name, "not_removed");
                assert!(
                    failed.message.contains(&left.display().to_string()),
                    "{failed:?}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"# mine\nadded\n");
        let rec = w.state.files.get(&key(&p)).cloned();
        assert!(rec.as_ref().is_some_and(|r| r.intent.is_none()), "{rec:?}");
        assert!(w.state.leftovers.contains_key(&key(&p)));
        // A file of the same shape that is not EnvCloak's stays.
        let foreign = temp(dir.path(), "CLAUDE.md", "new", "00000000000000b2");
        std::fs::write(&foreign, b"someone else's\n").unwrap_or_else(|e| panic!("{e}"));

        // The undo sweeps the leftover first, then gives the bytes back;
        // its rewrite is made and the unlink fails again.
        let left2 = temp(dir.path(), "CLAUDE.md", "swap", "00000000000000c3");
        std::fs::write(&left2, b"# mine\nadded\n").unwrap_or_else(|e| panic!("{e}"));
        INJECT.with(|c| {
            *c.borrow_mut() = Some(Inject::After(not_removed(Path::new(
                left2.file_name().unwrap_or_default(),
            ))));
        });
        let o = w.undo(&t, &mut nothing);
        assert!(
            matches!(&o, Outcome::Partial { made: Made::Changed, failed, .. } if failed.name == "not_removed"),
            "{o:?}"
        );
        assert!(!left.exists(), "the earlier leftover was swept");
        assert!(foreign.exists(), "a file that is not EnvCloak's stays");
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"# mine\n");
        assert!(w.state.files.is_empty());

        // A created file, its sync failing after the link: created.
        let q = dir.path().join("hooks.json");
        let tq = target(&q, false);
        INJECT.with(|c| {
            *c.borrow_mut() = Some(Inject::After(ModifyError {
                rel: PathBuf::from("hooks.json"),
                kind: envcloak_scan::ModifyErrorKind::Scan(ScanErrorKind::Io(
                    std::io::ErrorKind::Other,
                )),
            }));
        });
        let o = w.change(&tq, &mut append("{}\n"));
        assert!(
            matches!(
                &o,
                Outcome::Partial {
                    made: Made::Created,
                    ..
                }
            ),
            "{o:?}"
        );
        assert!(w.state.files.contains_key(&key(&q)));
        // Its removal made, the unlink of its moved-aside name failing
        // (its stamp unknown after the failed sync, so later than 2
        // minutes after its write).
        w.now = SystemTime::now() + Duration::from_secs(3600);
        let left3 = temp(dir.path(), "hooks.json", "del", "00000000000000d4");
        INJECT.with(|c| {
            *c.borrow_mut() = Some(Inject::After(not_removed(Path::new(
                left3.file_name().unwrap_or_default(),
            ))));
        });
        let o = w.undo(&tq, &mut nothing);
        assert!(
            matches!(&o, Outcome::Partial { made: Made::Removed, failed, .. } if failed.name == "not_removed"),
            "{o:?}"
        );
        assert!(!q.exists());
        assert!(w.state.files.is_empty());

        // A failure before the change: refused, the record before it back,
        // and the backup's result is the file as it was.
        std::fs::write(&p, b"# mine\n").unwrap_or_else(|e| panic!("{e}"));
        INJECT.with(|c| {
            *c.borrow_mut() = Some(Inject::Instead(ModifyError {
                rel: PathBuf::from("CLAUDE.md"),
                kind: envcloak_scan::ModifyErrorKind::Changed,
            }));
        });
        let o = w.change(&t, &mut append("added\n"));
        assert!(
            matches!(&o, Outcome::Refused(r) if r.name == "changed"),
            "{o:?}"
        );
        assert!(w.state.files.is_empty());
        assert_eq!(
            kept.results.last().map(|(_, d)| d.clone()),
            Some(sha256_hex(b"# mine\n"))
        );
    }

    /// The verifier's finding: the state's save after an undo failing was
    /// not tested. It is reported with the undo as made, for a rewrite and
    /// for a removal.
    ///
    /// Mutation checked: `self.journal.save(self.state).err()` after the
    /// undo's rewrite and removal answered `None`: the outcomes are
    /// `Changed` and `Removed`, and this fails.
    #[test]
    fn a_state_save_failing_after_an_undo_says_so() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("CLAUDE.md");
        std::fs::write(&p, b"# mine\n").unwrap_or_else(|e| panic!("{e}"));
        let q = dir.path().join("hooks.json");
        let (t, tq) = (target(&p, false), target(&q, false));
        let (mut state, mut saved, mut kept) =
            (State::default(), Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        assert!(matches!(
            w.change(&t, &mut append("added\n")),
            Outcome::Changed { .. }
        ));
        assert!(matches!(
            w.change(&tq, &mut append("{}\n")),
            Outcome::Changed { .. }
        ));
        // Each undo saves before its write (what it may leave) and after
        // it: the second fails.
        for (target, made) in [(&t, Made::Changed), (&tq, Made::Removed)] {
            let mut failing = Saved {
                fail: vec![2],
                ..Saved::default()
            };
            let mut w = writer!(&mut state, &mut failing, &mut kept);
            let o = w.undo(target, &mut nothing);
            assert!(
                matches!(&o, Outcome::Partial { made: m, failed, .. } if *m == made && failed.name == "state_unwritable"),
                "{o:?}"
            );
        }
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"# mine\n");
        assert!(!q.exists());
    }

    /// A key-shaped value made at run time (never a literal in the tree).
    fn canary(seed: u64) -> String {
        let mut x = seed | 1;
        (0..40)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                char::from(
                    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"[(x % 56) as usize],
                )
            })
            .collect()
    }

    /// The Codex review: a write stopped in the middle (the run killed)
    /// leaves a copy of the config, a literal key in it included, under a
    /// temporary name beside it. The digests of what the write could
    /// leave are saved before it, so the next run removes those copies:
    /// files of the temporary names' shape holding exactly those
    /// contents, or (under a name new contents are written under) their
    /// first bytes: a write stopped part way, the key already in it (the
    /// second Codex review: such a copy was skipped, and its record
    /// forgotten). Which contents a part is of is known once the next run
    /// has worked out what it writes, the same contents; until then the
    /// part stays, and so does the record, and the file is named
    /// (`leftovers_present`). Anything else stays and stays named: another
    /// digest, another shape. The leftovers here are laid out as
    /// `replace_atomically` names them (a run cannot be stopped inside it
    /// from a test), from the state as the stopped run saved it.
    ///
    /// Mutations checked: `expect_leftovers` adding nothing, and `sweep`
    /// returning at once: the copies are still there and this fails;
    /// `sweep` taking only whole copies (the previous digest check): the
    /// part holding the key stays and this fails; the record dropped
    /// whatever is left (the previous `kept` only for a failed removal):
    /// nothing is named while the part and the other file are there, and
    /// this fails.
    #[test]
    fn what_a_stopped_write_left_is_removed_by_the_next_run() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("settings.json");
        let key_text = canary(0x5eed);
        let before = format!("{{\"env\": {{\"K\": \"{key_text}\"}}}}\n").into_bytes();
        std::fs::write(&p, &before).unwrap_or_else(|e| panic!("{e}"));
        let t = target(&p, false);
        // The run's first save, its record and what it may leave, is all
        // that reached the disk.
        let (mut state, mut kept) = (State::default(), Kept::default());
        let mut saved = Saved {
            fail: vec![2],
            ..Saved::default()
        };
        // A change whose new contents differ from the old from their first
        // byte, so a part of them is no part of the file as it is.
        let mut comment = |b: Option<&[u8]>, _: Option<&FileRecord>| {
            let b = b.unwrap_or_default();
            if b.starts_with(b"// ") {
                return Ok(None);
            }
            let mut v = b"// ".to_vec();
            v.extend_from_slice(b);
            Ok(Some((v, vec![Edit::Block])))
        };
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let _ = w.change(&t, &mut comment);
        let on_disk = saved.saves.first().cloned().unwrap_or_default();
        let mut after = b"// ".to_vec();
        after.extend_from_slice(&before);
        // The run stopped with the old contents swapped out and the new
        // ones staged: the file itself as it was.
        std::fs::write(&p, &before).unwrap_or_else(|e| panic!("{e}"));
        let staged = temp(dir.path(), "settings.json", "new", "0123456789abcdef");
        let old = temp(dir.path(), "settings.json", "swap", "fedcba9876543210");
        std::fs::write(&staged, &after).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(&old, &before).unwrap_or_else(|e| panic!("{e}"));
        // Another write stopped part way: the new contents' first bytes,
        // the key's half included; and one stopped before its first byte.
        let cut = before.len() - 10;
        let part = temp(dir.path(), "settings.json", "new", "00000000000000aa");
        std::fs::write(&part, &after[..cut]).unwrap_or_else(|e| panic!("{e}"));
        let empty = temp(dir.path(), "settings.json", "new", "00000000000000bb");
        std::fs::write(&empty, b"").unwrap_or_else(|e| panic!("{e}"));
        let theirs = temp(dir.path(), "settings.json", "new", "1111111111111111");
        std::fs::write(&theirs, b"not EnvCloak's").unwrap_or_else(|e| panic!("{e}"));
        // The first bytes of something else, under a name of the shape
        // a whole file is moved to: not shown to be EnvCloak's.
        let moved_part = temp(dir.path(), "settings.json", "swap", "00000000000000cc");
        std::fs::write(&moved_part, &after[..cut]).unwrap_or_else(|e| panic!("{e}"));
        let odd = dir.path().join(".settings.json.envcloak-new-xyz.tmp");
        std::fs::write(&odd, &after).unwrap_or_else(|e| panic!("{e}"));
        let mut state = on_disk;
        assert!(state.leftovers.contains_key(&key(&p)));
        let (mut saved, mut kept) = (Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        // With the file as it is, whole copies go, and the empty part.
        w.sweep_all();
        assert!(!staged.exists() && !old.exists(), "EnvCloak's copies stay");
        assert!(!empty.exists(), "the empty part stays");
        assert!(part.exists(), "a part of what is not known yet went");
        assert!(theirs.exists() && odd.exists(), "another file was removed");
        assert!(w.state.leftovers.contains_key(&key(&p)), "the record went");
        assert_eq!(
            w.leftovers_present(),
            vec![part.clone(), theirs.clone(), moved_part.clone()]
        );
        // The next change of the file works out the same contents: the
        // part is of them, and goes.
        assert!(matches!(
            w.change(&t, &mut comment),
            Outcome::Changed { .. }
        ));
        assert!(!part.exists(), "the part holding the key stays");
        assert!(theirs.exists() && moved_part.exists() && odd.exists());
        assert_eq!(
            w.leftovers_present(),
            vec![theirs.clone(), moved_part.clone()]
        );
        // Gone, they are no longer named, and the record goes.
        std::fs::remove_file(&theirs).unwrap_or_else(|e| panic!("{e}"));
        std::fs::remove_file(&moved_part).unwrap_or_else(|e| panic!("{e}"));
        w.sweep_all();
        assert!(w.leftovers_present().is_empty());
        assert!(w.state.leftovers.is_empty());
        assert_eq!(std::fs::read(&p).unwrap_or_default(), after);
        // Nothing else holds the key beside the file but the person's own
        // file of another shape.
        let mut names: Vec<PathBuf> = std::fs::read_dir(dir.path())
            .unwrap_or_else(|e| panic!("{e}"))
            .flatten()
            .map(|e| e.path())
            .collect();
        names.sort();
        let mut want = vec![p.clone(), odd.clone()];
        want.sort();
        assert_eq!(names, want);
        assert!(String::from_utf8_lossy(&after).contains(&key_text));
    }

    /// A save of the state stopped part way leaves its new contents under a
    /// temporary name in `<data>/agents/`: the next open removes them (the
    /// class of the Codex review's finding: a stopped write's part was
    /// never removed). A file of that shape for another name stays.
    ///
    /// Mutation checked: `sweep_state_saves` not called in
    /// `StateFile::open`: the part stays and this fails.
    #[test]
    fn a_stopped_save_of_the_state_is_removed_when_it_is_opened() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let agents = dir.path().join("agents");
        std::fs::create_dir(&agents).unwrap_or_else(|e| panic!("{e}"));
        let part = temp(&agents, STATE_NAME, "new", "0123456789abcdef");
        std::fs::write(&part, b"{\"version\": 1, \"fi").unwrap_or_else(|e| panic!("{e}"));
        let other = temp(&agents, "other.json", "new", "0123456789abcdef");
        std::fs::write(&other, b"x").unwrap_or_else(|e| panic!("{e}"));
        let (_file, state) = StateFile::open(dir.path()).unwrap_or_else(|r| panic!("{r:?}"));
        assert!(state.files.is_empty());
        assert!(!part.exists(), "the stopped save is still there");
        assert!(other.exists());
    }

    /// A file EnvCloak wrote whole is removed only while it is what
    /// EnvCloak wrote; changed since, it is left, and the undo says why.
    ///
    /// Mutation checked: `install::structural` answering `Undo::Remove`
    /// for a whole file whatever it holds (the previous code): the
    /// person's edited file is removed and this fails.
    #[test]
    fn a_whole_file_changed_since_is_left_alone() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let p = dir.path().join("envcloak.rules");
        let (mut state, mut saved, mut kept) =
            (State::default(), Saved::default(), Kept::default());
        let mut w = writer!(&mut state, &mut saved, &mut kept);
        let t = target(&p, false);
        let mut whole = |b: Option<&[u8]>, _: Option<&FileRecord>| match b {
            Some(_) => Ok(None),
            None => Ok(Some((b"rule\n".to_vec(), vec![Edit::WholeFile]))),
        };
        assert!(matches!(w.change(&t, &mut whole), Outcome::Changed { .. }));
        std::fs::write(&p, b"rule\nmine\n").unwrap_or_else(|e| panic!("{e}"));
        // Older than 2 minutes: only the check of its contents keeps it.
        std::fs::File::options()
            .write(true)
            .open(&p)
            .and_then(|f| f.set_modified(SystemTime::now() - Duration::from_secs(600)))
            .unwrap_or_else(|e| panic!("{e}"));
        let o = w.undo(&t, &mut crate::install::structural);
        assert!(
            matches!(&o, Outcome::Refused(r) if r.name == "modified"),
            "{o:?}"
        );
        assert_eq!(std::fs::read(&p).unwrap_or_default(), b"rule\nmine\n");
    }
}
