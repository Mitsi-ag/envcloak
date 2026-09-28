//! A running `envcloakd` in a [`TestHome`], for tests that talk to it.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::home::TestHome;

/// How long a daemon may take to start listening.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// The daemon's runtime directory in `home`: under the data directory on
/// macOS, under `XDG_RUNTIME_DIR` (the home's `run/`) elsewhere.
pub fn daemon_run_dir(home: &TestHome) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.home().join("Library/Application Support/EnvCloak/run")
    } else {
        home.root().join("run/envcloak")
    }
}

/// The daemon's socket in `home`.
pub fn daemon_socket(home: &TestHome) -> PathBuf {
    daemon_run_dir(home).join("envcloakd.sock")
}

/// An `envcloakd --foreground` child in a test home, killed and reaped on
/// drop. Its standard error is collected as it runs.
#[derive(Debug)]
pub struct Daemon {
    child: Child,
    log: Arc<Mutex<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
}

impl Daemon {
    /// Starts `exe --foreground <args>` in `home`'s cleared environment
    /// and waits until it listens.
    ///
    /// # Panics
    /// When it exits or is not listening within 30 seconds; the message
    /// holds its standard error, which is value-free by design.
    pub fn start(home: &TestHome, exe: &Path, args: &[&str]) -> Daemon {
        let mut cmd = Command::new(exe);
        home.apply(&mut cmd);
        Self::start_command(cmd, args)
    }

    /// Starts `cmd` (an `envcloakd` command whose environment the caller
    /// set) with `--foreground <args>` and waits until it listens.
    ///
    /// # Panics
    /// As [`Daemon::start`].
    pub fn start_command(cmd: Command, args: &[&str]) -> Daemon {
        let mut d = Self::spawn_command(cmd, args);
        if !d.wait_listening(START_TIMEOUT) {
            let status = d.wait_exit(Duration::from_secs(1));
            panic!(
                "envcloakd did not start ({status:?}); its log:\n{}",
                d.log()
            );
        }
        d
    }

    /// Starts `exe --foreground <args>` in `home`'s environment without
    /// waiting, for tests of a daemon that must refuse to start.
    ///
    /// # Panics
    /// When the process cannot be started.
    pub fn spawn(home: &TestHome, exe: &Path, args: &[&str]) -> Daemon {
        let mut cmd = Command::new(exe);
        home.apply(&mut cmd);
        Self::spawn_command(cmd, args)
    }

    /// Starts `cmd --foreground <args>` without waiting.
    ///
    /// # Panics
    /// When the process cannot be started.
    pub fn spawn_command(mut cmd: Command, args: &[&str]) -> Daemon {
        cmd.arg("--foreground")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => panic!("cannot start envcloakd: {e}"),
        };
        let log = Arc::new(Mutex::new(Vec::new()));
        let reader = child.stderr.take().map(|err| {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                for line in BufReader::new(err).split(b'\n') {
                    let Ok(mut line) = line else { break };
                    line.push(b'\n');
                    log.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .extend_from_slice(&line);
                }
            })
        });
        Daemon { child, log, reader }
    }

    /// Everything the daemon wrote to standard error so far.
    pub fn log(&self) -> String {
        String::from_utf8_lossy(&self.log.lock().unwrap_or_else(PoisonError::into_inner))
            .into_owned()
    }

    /// The raw bytes of the log so far.
    pub fn log_bytes(&self) -> Vec<u8> {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).unwrap_or(-1)
    }

    /// Waits until the log holds a line containing `text`, or `limit`
    /// passes, or the daemon exits.
    pub fn wait_for_log(&mut self, text: &str, limit: Duration) -> bool {
        let end = Instant::now() + limit;
        loop {
            if self.log().contains(text) {
                return true;
            }
            if Instant::now() >= end || matches!(self.child.try_wait(), Ok(Some(_))) {
                // One last look: the reader may be behind the exit.
                std::thread::sleep(Duration::from_millis(50));
                return self.log().contains(text);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits until the daemon says it listens.
    pub fn wait_listening(&mut self, limit: Duration) -> bool {
        self.wait_for_log("envcloakd: listening", limit)
    }

    /// Sends `sig` (such as `-TERM`) with `kill`.
    ///
    /// # Panics
    /// When `kill` fails.
    pub fn signal(&self, sig: &str) {
        let ok = Command::new("kill")
            .args([sig, &self.pid().to_string()])
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "kill {sig} failed");
    }

    /// Waits up to `limit` for the daemon to exit, then collects the rest
    /// of its log. `None` when it is still running.
    pub fn wait_exit(&mut self, limit: Duration) -> Option<ExitStatus> {
        let end = Instant::now() + limit;
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                if let Some(r) = self.reader.take() {
                    let _ = r.join();
                }
                return Some(status);
            }
            if Instant::now() >= end {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(r) = self.reader.take() {
            let _ = r.join();
        }
    }
}
