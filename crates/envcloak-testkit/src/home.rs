//! An isolated HOME and XDG tree for tests that run EnvCloak binaries.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

use crate::canary::Canary;
use crate::detect::{Hit, sweep_dir};

/// The `PATH` [`TestHome::apply`] gives a child: system directories only.
pub const TEST_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Every variable [`TestHome::apply`] sets. A child started through it sees
/// these and nothing else from this process.
pub const TEST_ENV_VARS: [&str; 10] = [
    "PATH",
    "LANG",
    "TERM",
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR",
    "TMPDIR",
];

/// A temporary directory under `/tmp` with a short name (`/tmp/ecXXXXXX`),
/// so socket paths below it stay well under the 104-byte macOS `sun_path`
/// limit. It holds `home/`, `config/`, `data/`, `state/`, `cache/`, `tmp/`
/// and a mode-0700 `run/`, and is removed on drop.
#[derive(Debug)]
pub struct TestHome {
    dir: TempDir,
}

impl TestHome {
    /// # Panics
    /// When the directories cannot be created.
    pub fn new() -> Self {
        let dir = match tempfile::Builder::new().prefix("ec").tempdir_in("/tmp") {
            Ok(d) => d,
            Err(e) => panic!("cannot create a test home under /tmp: {e}"),
        };
        for sub in ["home", "config", "data", "state", "cache", "tmp", "run"] {
            if let Err(e) = std::fs::create_dir(dir.path().join(sub)) {
                panic!("cannot create {sub} in the test home: {e}");
            }
        }
        let run = dir.path().join("run");
        if let Err(e) = std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)) {
            panic!("cannot restrict the test runtime dir: {e}");
        }
        TestHome { dir }
    }

    /// The temporary root.
    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// The directory used as `HOME`.
    pub fn home(&self) -> PathBuf {
        self.root().join("home")
    }

    /// Clears the environment of `cmd`, so nothing exported in the
    /// developer's shell (tokens, cloud credentials) reaches the child or
    /// any core file it might leave. Then sets [`TEST_PATH`], `LANG=C` and
    /// `TERM=dumb`, and points `HOME`, every `XDG_*` base directory and
    /// `TMPDIR` into this tree. Call it before adding the command's own
    /// variables: it clears those too.
    pub fn apply<'c>(&self, cmd: &'c mut Command) -> &'c mut Command {
        let r = self.root();
        cmd.env_clear()
            .env("PATH", TEST_PATH)
            .env("LANG", "C")
            .env("TERM", "dumb")
            .env("HOME", r.join("home"))
            .env("XDG_CONFIG_HOME", r.join("config"))
            .env("XDG_DATA_HOME", r.join("data"))
            .env("XDG_STATE_HOME", r.join("state"))
            .env("XDG_CACHE_HOME", r.join("cache"))
            .env("XDG_RUNTIME_DIR", r.join("run"))
            .env("TMPDIR", r.join("tmp"))
    }

    /// Sweeps the whole tree for canaries.
    pub fn sweep(&self, cs: &[Canary]) -> Vec<Hit> {
        sweep_dir(self.root(), cs)
    }
}

impl Default for TestHome {
    fn default() -> Self {
        Self::new()
    }
}
