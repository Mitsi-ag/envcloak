//! An isolated HOME and XDG tree for tests that run EnvCloak binaries.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

use crate::canary::Canary;
use crate::detect::{Hit, assert_sweep_clean, sweep_dir};

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

/// Diagnostic settings [`TestHome::apply`] passes on from this process
/// when it has them. CI runs the whole suite at `RUST_LOG=trace` and
/// `RUST_BACKTRACE=full` (gate 12), and the programs the tests start run
/// at those settings too. They choose how much a program logs; they hold
/// no secret. No EnvCloak program reads `RUST_LOG` yet (there is no
/// logger); it is passed on so that logging added later is swept at its
/// most verbose. What gate 12 rests on is each test's own sweep of what it
/// captured.
pub const DIAGNOSTIC_VARS: [&str; 2] = ["RUST_LOG", "RUST_BACKTRACE"];

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
    /// `TERM=dumb`, points `HOME`, every `XDG_*` base directory and
    /// `TMPDIR` into this tree, and passes on the [`DIAGNOSTIC_VARS`] this
    /// process has. Call it before adding the command's own variables: it
    /// clears those too.
    pub fn apply<'c>(&self, cmd: &'c mut Command) -> &'c mut Command {
        cmd.env_clear().envs(self.vars())
    }

    /// The variables [`TestHome::apply`] sets, in the order of
    /// [`TEST_ENV_VARS`] and then of the [`DIAGNOSTIC_VARS`] this process
    /// has, for a child started some other way (a service manager's job,
    /// `env -i`).
    pub fn vars(&self) -> Vec<(&'static str, std::ffi::OsString)> {
        let r = self.root();
        let at = |sub: &str| r.join(sub).into_os_string();
        let mut vars = vec![
            ("PATH", TEST_PATH.into()),
            ("LANG", "C".into()),
            ("TERM", "dumb".into()),
            ("HOME", at("home")),
            ("XDG_CONFIG_HOME", at("config")),
            ("XDG_DATA_HOME", at("data")),
            ("XDG_STATE_HOME", at("state")),
            ("XDG_CACHE_HOME", at("cache")),
            ("XDG_RUNTIME_DIR", at("run")),
            ("TMPDIR", at("tmp")),
        ];
        vars.extend(
            DIAGNOSTIC_VARS
                .iter()
                .filter_map(|name| std::env::var_os(name).map(|v| (*name, v))),
        );
        vars
    }

    /// Keeps the tree instead of removing it, and returns its root: for a
    /// measurement made by hand, whose author looks at what was written.
    pub fn keep(self) -> PathBuf {
        self.dir.keep()
    }

    /// Sweeps the whole tree for canaries.
    pub fn sweep(&self, cs: &[Canary]) -> Vec<Hit> {
        sweep_dir(self.root(), cs)
    }

    /// Panics if the tree holds any canary, listing the hits without
    /// values (see [`assert_sweep_clean`]).
    pub fn assert_clean(&self, cs: &[Canary]) {
        assert_sweep_clean(self.root(), cs);
    }
}

impl Default for TestHome {
    fn default() -> Self {
        Self::new()
    }
}
