//! The probe home on a person's machine (M2 plan task M2-28): a directory
//! of the probe's own, where `envcloak agents status --probe` runs its
//! daemon, its throwaway vault and the agent host it probes, so nothing of
//! the person's is used and nothing of the person's is touched.
//!
//! [`ProbeHome::create`] makes `/tmp/ecpXXXXXX` (the system's temporary
//! directory, resolved: `/private/tmp` on macOS), mode 0700, with a name no
//! other entry has (`mkdir`, which never follows a link and fails on any
//! name already there), and checks it: a directory, not a link, owned by
//! this user, open to no one else. It is short on purpose, never under
//! EnvCloak's data directory: on macOS the daemon's socket is
//! `$HOME/Library/Application Support/EnvCloak/run/envcloakd.sock`, so a
//! home under `~/Library/Application Support/EnvCloak/probe/<run>` would
//! give a socket path of about 120 bytes for `/Users/` and a 20-character
//! name, past the 104 bytes `sun_path` holds (`envcloak_ipc::SUN_PATH_MAX`).
//!
//! Inside it, as the agent harness's test homes are laid out (so the host
//! runs here as it runs in CI): `home/` (`HOME`), `config/`, `data/`,
//! `state/`, `cache/`, `run/` (mode 0700), `tmp/` and `claude-tmp/`, and
//! `home/.codex`. [`ProbeHome::env`] is the environment everything the
//! probe starts gets, after a cleared one: `HOME`, every `XDG_*` base
//! directory (`XDG_RUNTIME_DIR` in the probe home: on Linux the daemon's
//! socket depends on it, not on `HOME`, so the person's value would put
//! the probe's daemon on the person's socket), `TMPDIR`, `CODEX_HOME`, and
//! `CLAUDE_CODE_TMPDIR`, which the pinned Claude Code follows where it
//! ignores `TMPDIR` (it writes under `/tmp` otherwise, docs/AGENTS.md "Host
//! behaviour"). `CLAUDE_CONFIG_DIR` is left unset, as in CI: the
//! environment is cleared, so the person's value never reaches the host,
//! and with it unset Claude Code reads its settings from the probe's `HOME`
//! exactly as the probes were qualified.
//!
//! The probe's socket path is computed with `envcloak-ipc`'s own resolver
//! from that environment ([`ProbeHome::socket_path`]); the home is refused
//! unless the path fits `sun_path` and differs from the person's.
//!
//! A marker file, [`MARKER`], is in it from the start, held under an
//! exclusive `flock` for as long as the run keeps the [`ProbeHome`]: put
//! there under a temporary name, locked, then renamed, so no other run ever
//! sees it unlocked while this one is starting. [`ProbeHome::remove`] takes
//! the home away at the end of a run. A run that was killed (`kill -9`)
//! leaves it, unlocked, since the kernel drops a `flock` with its last
//! descriptor: [`sweep`], at the start of the next run, removes every
//! `ecp*` directory of this user in the temporary directory that holds the
//! marker and whose marker is not locked, and leaves anything else, a
//! directory of another run that is still going included.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use envcloak_core::vault::{Platform, data_dir_for};
use envcloak_ipc::{RunPathErrorKind, RunPaths};

/// The directory probe homes are made in.
pub const TMP: &str = "/tmp";
/// The start of a probe home's name.
pub const PREFIX: &str = "ecp";
/// How many random characters follow it.
pub const SUFFIX_LEN: usize = 6;
/// The marker file in a probe home.
pub const MARKER: &str = ".envcloak-probe-home";
/// What the marker holds.
const MARKER_TEXT: &str = "A probe home of `envcloak agents status --probe` (M2-28): removed when \
                           its run ends, or by the next run.\n";

/// Why no probe home could be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    /// The temporary directory is not one a private directory can be made
    /// in, or the directory made there is not private to this user.
    NotPrivate,
    /// The probe daemon's socket path would not fit `sun_path`.
    SocketTooLong,
    /// The probe daemon's socket would be the person's own daemon's.
    PersonsSocket,
    /// The system refused something else.
    Io(io::ErrorKind),
}

impl ProbeError {
    /// Its token.
    pub fn name(self) -> &'static str {
        match self {
            ProbeError::NotPrivate => "probe_home_not_private",
            ProbeError::SocketTooLong => "probe_socket_too_long",
            ProbeError::PersonsSocket => "probe_socket_is_yours",
            ProbeError::Io(_) => "io",
        }
    }

    /// What it means, value-free.
    pub fn message(self) -> &'static str {
        match self {
            ProbeError::NotPrivate => {
                "the probe home could not be made private to you in the temporary directory"
            }
            ProbeError::SocketTooLong => {
                "the probe daemon's socket path would be longer than a Unix socket path can be"
            }
            ProbeError::PersonsSocket => {
                "the probe daemon's socket would be your own daemon's; nothing was started"
            }
            ProbeError::Io(_) => "the probe home could not be made",
        }
    }
}

impl From<io::Error> for ProbeError {
    fn from(e: io::Error) -> Self {
        ProbeError::Io(e.kind())
    }
}

/// A probe home, removed by [`ProbeHome::remove`] (or, failing that, when
/// dropped, or by the next run's [`sweep`]).
pub struct ProbeHome {
    root: PathBuf,
    /// The marker, open and locked for as long as this lives.
    marker: Option<File>,
    socket: PathBuf,
}

impl std::fmt::Debug for ProbeHome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeHome")
            .field("root", &self.root)
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

/// The directories made in a probe home, with their modes.
const DIRS: [(&str, u32); 9] = [
    ("home", 0o700),
    ("config", 0o700),
    ("data", 0o700),
    ("state", 0o700),
    ("cache", 0o700),
    ("run", 0o700),
    ("tmp", 0o700),
    ("claude-tmp", 0o700),
    ("home/.codex", 0o700),
];

impl ProbeHome {
    /// A new probe home in [`TMP`], refused when its socket would be the
    /// person's (from this process's `HOME`, `XDG_RUNTIME_DIR` and
    /// `XDG_STATE_HOME`).
    ///
    /// # Errors
    /// See [`ProbeError`]; nothing is left behind.
    pub fn create() -> Result<ProbeHome, ProbeError> {
        let person = RunPaths::for_user().ok().map(|p| p.socket);
        ProbeHome::create_in(Path::new(TMP), person.as_deref())
    }

    /// A new probe home in `tmp`, refused when its socket would be
    /// `person_socket`.
    ///
    /// # Errors
    /// See [`ProbeError`]; nothing is left behind.
    pub fn create_in(tmp: &Path, person_socket: Option<&Path>) -> Result<ProbeHome, ProbeError> {
        let tmp = std::fs::canonicalize(tmp)?;
        let root = make_private_dir(&tmp)?;
        let mut home = ProbeHome {
            root,
            marker: None,
            socket: PathBuf::new(),
        };
        // From here, anything that fails takes the directory away with it
        // (`Drop`).
        home.fill()?;
        let paths = home.run_paths()?;
        refuse_persons(&paths.socket, person_socket)?;
        home.socket = paths.socket;
        Ok(home)
    }

    /// The directories, then the marker, locked.
    fn fill(&mut self) -> Result<(), ProbeError> {
        for (dir, mode) in DIRS {
            std::fs::DirBuilder::new()
                .mode(mode)
                .create(self.root.join(dir))?;
        }
        let mut rnd = [0u8; 8];
        getrandom::fill(&mut rnd).map_err(|_| ProbeError::Io(io::ErrorKind::Other))?;
        let staged = self
            .root
            .join(format!("{MARKER}.{}", crate::coverage::hex(&rnd)));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staged)?;
        if !envcloak_sys::try_lock_exclusive(&f)? {
            return Err(ProbeError::NotPrivate);
        }
        f.write_all(MARKER_TEXT.as_bytes())?;
        std::fs::rename(&staged, self.root.join(MARKER))?;
        self.marker = Some(f);
        Ok(())
    }

    /// The probe home's directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `HOME`.
    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// `CODEX_HOME`.
    pub fn codex_home(&self) -> PathBuf {
        self.home().join(".codex")
    }

    /// `CLAUDE_CODE_TMPDIR`.
    pub fn claude_tmp(&self) -> PathBuf {
        self.root.join("claude-tmp")
    }

    /// The environment of everything the probe starts, after a cleared
    /// one (`PATH` is the caller's to add): see the module documentation.
    pub fn env(&self) -> Vec<(OsString, OsString)> {
        let at = |sub: &str| self.root.join(sub).into_os_string();
        vec![
            ("HOME".into(), self.home().into_os_string()),
            ("XDG_CONFIG_HOME".into(), at("config")),
            ("XDG_DATA_HOME".into(), at("data")),
            ("XDG_STATE_HOME".into(), at("state")),
            ("XDG_CACHE_HOME".into(), at("cache")),
            ("XDG_RUNTIME_DIR".into(), at("run")),
            ("TMPDIR".into(), at("tmp")),
            ("CODEX_HOME".into(), self.codex_home().into_os_string()),
            (
                "CLAUDE_CODE_TMPDIR".into(),
                self.claude_tmp().into_os_string(),
            ),
            ("LANG".into(), "C".into()),
            ("TERM".into(), "dumb".into()),
        ]
    }

    /// The value of `name` in [`ProbeHome::env`].
    fn var(&self, name: &str) -> Option<OsString> {
        self.env()
            .into_iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }

    /// The probe daemon's runtime paths, by `envcloak-ipc`'s own resolver
    /// from [`ProbeHome::env`].
    ///
    /// # Errors
    /// [`ProbeError::SocketTooLong`] when the socket path would not fit
    /// `sun_path`.
    pub fn run_paths(&self) -> Result<RunPaths, ProbeError> {
        let home = self.var("HOME");
        let runtime = self.var("XDG_RUNTIME_DIR");
        let state = self.var("XDG_STATE_HOME");
        RunPaths::resolve(
            Platform::current(),
            home.as_deref(),
            runtime.as_deref(),
            state.as_deref(),
        )
        .map_err(|e| match e.kind() {
            RunPathErrorKind::SocketPathTooLong => ProbeError::SocketTooLong,
            _ => ProbeError::NotPrivate,
        })
    }

    /// The probe daemon's socket.
    pub fn socket_path(&self) -> PathBuf {
        self.socket.clone()
    }

    /// The probe daemon's data directory (its vault).
    ///
    /// # Errors
    /// Never, in practice: `HOME` is absolute.
    pub fn data_dir(&self) -> Result<PathBuf, ProbeError> {
        let home = self.var("HOME");
        let data = self.var("XDG_DATA_HOME");
        data_dir_for(Platform::current(), home.as_deref(), data.as_deref())
            .map_err(|_| ProbeError::NotPrivate)
    }

    /// Removes the probe home, its marker last held.
    ///
    /// # Errors
    /// When it could not be removed whole: what is left is the next run's
    /// to sweep (its marker no longer locked).
    pub fn remove(mut self) -> io::Result<()> {
        let done = remove_tree(&self.root);
        self.marker = None;
        // Nothing for `Drop` to do now, whatever the result.
        self.root = PathBuf::new();
        done
    }
}

impl Drop for ProbeHome {
    fn drop(&mut self) {
        if !self.root.as_os_str().is_empty() {
            let _ = remove_tree(&self.root);
        }
    }
}

/// Removes `dir` and everything in it, never following a link
/// (`std::fs::remove_dir_all` works from directory descriptors with
/// `O_NOFOLLOW`). A directory already gone is removed.
fn remove_tree(dir: &Path) -> io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Refuses a probe socket that is the person's.
fn refuse_persons(socket: &Path, person: Option<&Path>) -> Result<(), ProbeError> {
    if person.is_some_and(|p| same_path(p, socket)) {
        return Err(ProbeError::PersonsSocket);
    }
    Ok(())
}

/// Whether two socket paths name the same place: equal, or equal once
/// their directories are resolved (a person's `XDG_RUNTIME_DIR` given
/// through a link).
fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    let resolved = |p: &Path| {
        let dir = std::fs::canonicalize(p.parent()?).ok()?;
        Some(dir.join(p.file_name()?))
    };
    matches!((resolved(a), resolved(b)), (Some(x), Some(y)) if x == y)
}

/// Makes `<tmp>/ecpXXXXXX`, mode 0700, and checks it.
fn make_private_dir(tmp: &Path) -> Result<PathBuf, ProbeError> {
    for _ in 0..32 {
        let mut rnd = [0u8; SUFFIX_LEN];
        getrandom::fill(&mut rnd).map_err(|_| ProbeError::Io(io::ErrorKind::Other))?;
        let suffix: String = rnd
            .iter()
            .map(|b| char::from(b"abcdefghijklmnopqrstuvwxyz0123456789"[usize::from(*b) % 36]))
            .collect();
        let root = tmp.join(format!("{PREFIX}{suffix}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
        let m = std::fs::symlink_metadata(&root)?;
        let private = m.is_dir()
            && !m.file_type().is_symlink()
            && m.uid() == envcloak_sys::effective_uid()
            && m.mode() & 0o077 == 0;
        if !private {
            // Ours by its `mkdir`, so ours to take away again; anything
            // else there is left as it is.
            let _ = std::fs::remove_dir(&root);
            return Err(ProbeError::NotPrivate);
        }
        return Ok(root);
    }
    Err(ProbeError::NotPrivate)
}

/// What [`sweep`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Swept {
    /// Probe homes of runs that ended without removing them, removed now.
    pub removed: usize,
    /// Probe homes of runs still going (their marker locked), left.
    pub in_use: usize,
    /// Probe homes of ended runs that could not be removed whole.
    pub failed: Vec<PathBuf>,
}

/// Whether `name` is a probe home's: [`PREFIX`] and [`SUFFIX_LEN`] letters
/// and digits.
pub fn probe_home_name(name: &str) -> bool {
    name.strip_prefix(PREFIX).is_some_and(|rest| {
        rest.len() == SUFFIX_LEN && rest.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

/// Removes the probe homes earlier runs left in `tmp` (see the module
/// documentation): each `ecp*` directory of this user, not a link, holding
/// [`MARKER`] as a regular file of this user that no run holds locked.
/// Anything else is left as it is.
pub fn sweep(tmp: &Path) -> Swept {
    let mut out = Swept::default();
    let Ok(tmp) = std::fs::canonicalize(tmp) else {
        return out;
    };
    let Ok(entries) = std::fs::read_dir(&tmp) else {
        return out;
    };
    let uid = envcloak_sys::effective_uid();
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_str().is_some_and(probe_home_name) {
            continue;
        }
        let root = tmp.join(&name);
        let Ok(m) = std::fs::symlink_metadata(&root) else {
            continue;
        };
        if !m.is_dir() || m.file_type().is_symlink() || m.uid() != uid {
            continue;
        }
        let marker = root.join(MARKER);
        let mine = std::fs::symlink_metadata(&marker)
            .is_ok_and(|m| m.file_type().is_file() && m.uid() == uid);
        if !mine {
            continue;
        }
        let Ok(f) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&marker)
        else {
            continue;
        };
        match envcloak_sys::try_lock_exclusive(&f) {
            Ok(true) => {}
            Ok(false) => {
                out.in_use += 1;
                continue;
            }
            Err(_) => continue,
        }
        // Held now, so no run can be starting here (a run holds its marker
        // from before it is named so): the directory is an ended run's.
        if remove_tree(&root).is_ok() {
            out.removed += 1;
        } else {
            out.failed.push(root);
        }
        drop(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("ecq")
            .tempdir_in("/tmp")
            .unwrap()
    }

    #[test]
    fn a_probe_home_is_private_marked_and_short() {
        let t = tmp();
        let h = ProbeHome::create_in(t.path(), None).unwrap();
        let m = std::fs::symlink_metadata(h.root()).unwrap();
        assert!(m.is_dir());
        assert_eq!(m.mode() & 0o777, 0o700);
        let name = h.root().file_name().unwrap().to_str().unwrap();
        assert!(probe_home_name(name), "{name}");
        assert!(h.root().join(MARKER).is_file());
        assert!(h.socket_path().starts_with(h.root()));
        let root = h.root().to_path_buf();
        h.remove().unwrap();
        assert!(!root.exists());
    }

    /// A probe socket that is the person's, by the same path or through a
    /// link to its directory, is refused; another is not. A dropped home
    /// takes its directory with it.
    #[test]
    fn the_persons_socket_is_refused() {
        let t = tmp();
        let h = ProbeHome::create_in(t.path(), None).unwrap();
        let socket = h.socket_path();
        let dir = socket.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let by_link = link.join(socket.file_name().unwrap());
        assert_eq!(
            refuse_persons(&socket, Some(&socket)),
            Err(ProbeError::PersonsSocket)
        );
        assert_eq!(
            refuse_persons(&socket, Some(&by_link)),
            Err(ProbeError::PersonsSocket)
        );
        assert_eq!(refuse_persons(&socket, Some(&t.path().join("s"))), Ok(()));
        assert_eq!(refuse_persons(&socket, None), Ok(()));
        let root = h.root().to_path_buf();
        drop(h);
        assert!(!root.exists(), "the dropped home was removed");
    }

    /// Everything the probe starts gets `HOME`, every `XDG_*` base
    /// directory, `TMPDIR`, `CODEX_HOME` and `CLAUDE_CODE_TMPDIR` inside the
    /// probe home, whatever this process has, and its socket is there too
    /// on both systems. Mutation checked: `XDG_RUNTIME_DIR` taken from this
    /// process's environment (the person's, on Linux the person's socket):
    /// it is then outside the probe home and this test fails.
    #[test]
    fn the_probe_environment_is_all_inside_the_probe_home() {
        let t = tmp();
        let h = ProbeHome::create_in(t.path(), None).unwrap();
        let env = h.env();
        for name in [
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "XDG_RUNTIME_DIR",
            "TMPDIR",
            "CODEX_HOME",
            "CLAUDE_CODE_TMPDIR",
        ] {
            let v = env
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| PathBuf::from(v))
                .unwrap_or_else(|| panic!("{name} unset"));
            assert!(v.starts_with(h.root()), "{name}: {}", v.display());
        }
        assert!(env.iter().all(|(k, _)| k != "CLAUDE_CONFIG_DIR"));
        let paths = h.run_paths().unwrap();
        assert!(paths.socket.starts_with(h.root()));
        assert!(paths.socket.as_os_str().len() <= envcloak_ipc::SUN_PATH_MAX);
        h.remove().unwrap();
    }

    #[test]
    fn names_are_told_apart() {
        assert!(probe_home_name("ecpab12cd"));
        for bad in [
            "ecp",
            "ecpab12c",
            "ecpab12cde",
            "ecpab-2cd",
            "ecxab12cd",
            "ecpab12c\u{e9}",
        ] {
            assert!(!probe_home_name(bad), "{bad}");
        }
    }

    /// A run's own home is never swept while the run holds it; once it
    /// ended (the [`ProbeHome`] forgotten, as `kill -9` leaves it, and its
    /// marker no longer held), the next sweep removes it; a directory with
    /// the name and no marker, and one whose marker is a link, are left.
    #[test]
    fn the_sweep_takes_only_ended_runs_homes() {
        let t = tmp();
        let live = ProbeHome::create_in(t.path(), None).unwrap();
        let ended = ProbeHome::create_in(t.path(), None).unwrap();
        let ended_root = ended.root().to_path_buf();
        // Forget it without removing it, its marker closed: what a killed
        // run leaves.
        let mut ended = ended;
        ended.marker = None;
        let kept_root = std::mem::take(&mut ended.root);
        std::mem::forget(ended);
        assert_eq!(kept_root, ended_root);
        let root = std::fs::canonicalize(t.path()).unwrap();
        let unmarked = root.join("ecpzzzzzz");
        std::fs::create_dir(&unmarked).unwrap();
        let linked = root.join("ecpyyyyyy");
        std::fs::create_dir(&linked).unwrap();
        std::os::unix::fs::symlink(live.root().join(MARKER), linked.join(MARKER)).unwrap();

        let swept = sweep(t.path());
        assert_eq!(swept.removed, 1, "{swept:?}");
        assert_eq!(swept.in_use, 1, "{swept:?}");
        assert!(swept.failed.is_empty());
        assert!(!ended_root.exists());
        assert!(live.root().exists());
        assert!(unmarked.exists());
        assert!(linked.exists());
        live.remove().unwrap();
    }
}
