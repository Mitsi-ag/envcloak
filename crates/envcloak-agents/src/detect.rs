//! Which agent hosts are installed, and which version (SPEC §7.2 rule 1;
//! M2 plan M2-08): a host's executable found on `PATH` and asked for its
//! `--version`, with a cleared environment and a 5 second limit, and the
//! answer read strictly. An answer of any other shape is not a version:
//! the installer writes only the formats of a product it recognized.
//!
//! - Claude Code prints `<version> (Claude Code)`.
//! - Codex prints `codex-cli <version>` (and may warn on standard error).
//!
//! A version is `<major>.<minor>.<patch>`, each a run of digits, with an
//! optional `-<pre-release>` of letters, digits and dots.

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::hook::Host;

/// How long `--version` may take.
pub const LIMIT: Duration = Duration::from_secs(5);
/// The most output `--version` may print that is read.
const MAX_OUTPUT: u64 = 4096;

/// An installed host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub host: Host,
    /// The executable found on `PATH`.
    pub exe: PathBuf,
    pub version: String,
}

/// Why a host was not detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectError {
    /// No executable of the host's name on `PATH`.
    NotFound,
    /// `--version` did not finish within [`LIMIT`].
    Timeout,
    /// `--version` failed, or printed something that is not this host's
    /// version line.
    NotRecognized,
    /// The executable could not be read whole, or was another before and
    /// after it answered `--version` ([`detect_identified`]): the version
    /// is then not known to be that of any one binary.
    Changed,
}

impl DetectError {
    pub fn name(self) -> &'static str {
        match self {
            DetectError::NotFound => "not_installed",
            DetectError::Timeout => "version_timeout",
            DetectError::NotRecognized => "not_recognized",
            DetectError::Changed => "changed_while_asked",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            DetectError::NotFound => "not installed (no executable of its name on PATH)",
            DetectError::Timeout => "its --version did not answer within 5 seconds",
            DetectError::NotRecognized => {
                "its --version did not print this product's version line, so EnvCloak does not \
                 know which format to write"
            }
            DetectError::Changed => {
                "its executable could not be read whole, or changed while it was asked its \
                 version, so the version is not known to be that of the binary there now"
            }
        }
    }
}

/// The executable's name on `PATH`.
pub fn exe_name(host: Host) -> &'static str {
    match host {
        Host::ClaudeCode => "claude",
        Host::Codex => "codex",
    }
}

/// The first executable regular file named `name` in the directories of
/// `path` (a `PATH` value); relative directories are skipped.
pub fn find_on_path(name: &str, path: &OsStr) -> Option<PathBuf> {
    path.as_bytes()
        .split(|&b| b == b':')
        .map(|d| Path::new(OsStr::from_bytes(d)))
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| {
            std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

/// Reads a version line: Claude Code's or Codex's.
pub fn parse_version(host: Host, stdout: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(stdout).ok()?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.contains('\n') || line.contains('\r') {
        return None;
    }
    let v = match host {
        Host::ClaudeCode => line.strip_suffix(" (Claude Code)")?,
        Host::Codex => line.strip_prefix("codex-cli ")?,
    };
    is_version(v).then(|| v.to_owned())
}

fn is_version(v: &str) -> bool {
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit()))
        && pre.is_none_or(|p| {
            !p.is_empty()
                && p.len() <= 64
                && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
        })
}

/// Finds `host` on `path` and asks it for its version, with only `HOME`,
/// `PATH` and the host's own location variable (`CODEX_HOME`,
/// `CLAUDE_CONFIG_DIR`) from `env` in its environment.
pub fn detect(
    host: Host,
    path: &OsStr,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Detected, DetectError> {
    let exe = find_on_path(exe_name(host), path).ok_or(DetectError::NotFound)?;
    let mut cmd = Command::new(&exe);
    cmd.arg("--version")
        .env_clear()
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let own = match host {
        Host::ClaudeCode => "CLAUDE_CONFIG_DIR",
        Host::Codex => "CODEX_HOME",
    };
    for k in ["HOME", own] {
        if let Some(v) = env(k) {
            cmd.env(k, v);
        }
    }
    version_of(host, exe, &mut cmd)
}

/// Finds `host` on `path` and asks it for its version with `vars` and
/// `PATH` alone in its environment: for `agents status --probe` (M2-28),
/// whose `vars` are a probe home's (`probe::home::ProbeHome::env`), so the
/// host, or a launcher in its place, reads and writes nothing of the
/// person's while it answers (Codex review of M2-28: the version was asked
/// with the person's `HOME`, `CODEX_HOME` and `CLAUDE_CONFIG_DIR`).
pub fn detect_with(
    host: Host,
    path: &OsStr,
    vars: &[(OsString, OsString)],
) -> Result<Detected, DetectError> {
    let exe = find_on_path(exe_name(host), path).ok_or(DetectError::NotFound)?;
    let mut cmd = Command::new(&exe);
    cmd.arg("--version")
        .env_clear()
        .envs(vars.iter().map(|(k, v)| (k, v)))
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some((_, home)) = vars.iter().find(|(k, _)| k == "HOME") {
        cmd.current_dir(home);
    }
    version_of(host, exe, &mut cmd)
}

/// [`detect_with`], with the version bound to one binary (Codex review of
/// M2-28: the version was asked before the binary was hashed, so a host
/// updated in between ran under the old version's qualification): the
/// executable `PATH` leads to is resolved and hashed before `--version`
/// and again after it, and the two must be the same, readable bytes.
/// Gives the SHA-256 the version is that of; whatever is measured later
/// (`probe::run_surfaces` hashes the binary before and after its runs) is
/// compared with it, so a binary replaced at any point after the first
/// hash is never credited with this version's result.
///
/// # Errors
/// As [`detect_with`], and [`DetectError::Changed`].
pub fn detect_identified(
    host: Host,
    path: &OsStr,
    vars: &[(OsString, OsString)],
) -> Result<(Detected, String), DetectError> {
    let exe = find_on_path(exe_name(host), path).ok_or(DetectError::NotFound)?;
    let digest = || {
        std::fs::canonicalize(&exe)
            .ok()
            .and_then(|p| crate::coverage::file_sha256(&p))
    };
    let before = digest().ok_or(DetectError::Changed)?;
    let d = detect_with(host, path, vars)?;
    if d.exe != exe || digest().as_deref() != Some(before.as_str()) {
        return Err(DetectError::Changed);
    }
    Ok((d, before))
}

/// Runs `cmd` (`exe --version`) and reads `host`'s version from it.
fn version_of(host: Host, exe: PathBuf, cmd: &mut Command) -> Result<Detected, DetectError> {
    let out = run_limited(cmd, LIMIT).map_err(|timed_out| {
        if timed_out {
            DetectError::Timeout
        } else {
            DetectError::NotRecognized
        }
    })?;
    let version = parse_version(host, &out).ok_or(DetectError::NotRecognized)?;
    Ok(Detected { host, exe, version })
}

/// Runs `cmd`, reading at most [`MAX_OUTPUT`] bytes of its standard
/// output, and returns that output when it exits 0 within `limit`.
/// `Err(true)` is a timeout, `Err(false)` a failure.
fn run_limited(cmd: &mut Command, limit: Duration) -> Result<Vec<u8>, bool> {
    match run_bounded(cmd, limit, MAX_OUTPUT) {
        Ok(out) if out.status.success() => Ok(out.stdout),
        Ok(_) => Err(false),
        Err(Bounded::Timeout) => Err(true),
        Err(Bounded::Failed) => Err(false),
    }
}

/// Starts `cmd` as a child that stays this process's own until it waits
/// for it (D-34): the kernel is first made not to reap this process's
/// children on its own (`envcloak_sys::owned::keep_children_unreaped`),
/// since a SIGCHLD inherited ignored, or set with `SA_NOCLDWAIT` by
/// whatever started `envcloak`, would have the child reaped the moment it
/// exits, its pid and process group free for another process's use while
/// the probes still signal them by number (the verifier's review of
/// M2-28). Every child the probes and the host detection start, and later
/// signal or wait for, is started here.
///
/// # Errors
/// When SIGCHLD cannot be made to leave children unreaped (nothing is
/// started then), or `spawn`'s own.
pub fn spawn_unreaped(cmd: &mut Command) -> std::io::Result<Child> {
    envcloak_sys::owned::keep_children_unreaped()?;
    cmd.spawn()
}

/// Why [`run_bounded`] has no output to give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bounded {
    /// The command, or the reading of its output, was not done in time.
    Timeout,
    /// It could not be started.
    Failed,
}

/// A pipe's contents, read on a thread of its own, at most `max` bytes.
fn read_pipe(pipe: Option<impl Read + Send + 'static>, max: u64) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        if let Some(p) = pipe {
            let _ = p.take(max).read_to_end(&mut out);
        }
        let _ = tx.send(out);
    });
    rx
}

/// Runs `cmd` with its standard output and error piped, and has its exit
/// status and at most `max` bytes of each within `limit` of its start, or
/// [`Bounded::Timeout`]. The whole wait is bounded, the reading of the
/// output included: a process the command left behind that keeps a pipe
/// open (Codex review) ends the wait at the limit, its reader left to
/// finish on its own. A command past the limit is killed while it is
/// this process's own unreaped child (D-34), then reaped.
pub(crate) fn run_bounded(cmd: &mut Command, limit: Duration, max: u64) -> Result<Output, Bounded> {
    let start = Instant::now();
    let deadline = start + limit;
    let mut child = spawn_unreaped(cmd).map_err(|_| Bounded::Failed)?;
    let out_rx = read_pipe(child.stdout.take(), max);
    let err_rx = read_pipe(child.stderr.take(), max);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => break None,
            // Not this process's child any more (reaped behind its back):
            // its pid may be another process's, so nothing is sent.
            Err(_) => return Err(Bounded::Failed),
        }
    };
    let Some(status) = status else {
        // Still this process's unreaped child (`spawn_unreaped`): the
        // signal reaches it, and the wait reaps it.
        let _ = child.kill();
        let _ = child.wait();
        return Err(Bounded::Timeout);
    };
    let left = || deadline.saturating_duration_since(Instant::now());
    let stdout = out_rx.recv_timeout(left()).map_err(|_| Bounded::Timeout)?;
    let stderr = err_rx.recv_timeout(left()).map_err(|_| Bounded::Timeout)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_lines_are_read_strictly() {
        assert_eq!(
            parse_version(Host::ClaudeCode, b"2.1.280 (Claude Code)\n").as_deref(),
            Some("2.1.280")
        );
        assert_eq!(
            parse_version(Host::Codex, b"codex-cli 0.159.2\n").as_deref(),
            Some("0.159.2")
        );
        assert_eq!(
            parse_version(Host::Codex, b"codex-cli 0.160.0-alpha.3").as_deref(),
            Some("0.160.0-alpha.3")
        );
        for bad in [
            &b"2.1.280 (Claude Code)\nextra\n"[..],
            b"2.1 (Claude Code)\n",
            b"v2.1.280 (Claude Code)\n",
            b"2.1.280 (Codex)\n",
            b"",
            b"\xff",
            b"2.1.280 (Claude Code)\r\n",
        ] {
            assert_eq!(parse_version(Host::ClaudeCode, bad), None, "{bad:?}");
        }
        assert_eq!(parse_version(Host::Codex, b"2.1.280 (Claude Code)\n"), None);
    }

    /// The version is bound to the binary that answered it (Codex review
    /// of M2-28): an executable replaced while it is asked its version
    /// (here, by itself, as an update in between would) is
    /// `changed_while_asked`, never the old version with the new binary's
    /// digest. Mutation checked: `detect_identified` without its second
    /// hash: the replaced binary is given the first answer's version and
    /// this fails.
    #[test]
    fn a_binary_replaced_while_asked_its_version_has_no_version() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let fake = dir.path().join("claude");
        let write = |body: &str| {
            std::fs::write(&fake, body).unwrap_or_else(|e| panic!("{e}"));
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
                .unwrap_or_else(|e| panic!("{e}"));
        };
        let vars = [(OsString::from("HOME"), dir.path().as_os_str().to_owned())];
        let path = dir.path().as_os_str().to_owned();
        // A binary that stays as it is: its version and its digest.
        write("#!/bin/sh\necho '2.1.280 (Claude Code)'\n");
        let (d, sha) =
            detect_identified(Host::ClaudeCode, &path, &vars).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(d.version, "2.1.280");
        assert_eq!(
            Some(sha),
            crate::coverage::file_sha256(&std::fs::canonicalize(&fake).unwrap_or_default())
        );
        // One replaced while it answers (an update landing then): the
        // answer is the old version's, the binary there after it another.
        let next = dir.path().join("next");
        std::fs::write(&next, "#!/bin/sh\necho '2.1.999 (Claude Code)'\n")
            .unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("{e}"));
        write(&format!(
            "#!/bin/sh\n/bin/mv '{}' '{}'\necho '2.1.280 (Claude Code)'\n",
            next.display(),
            fake.display()
        ));
        assert_eq!(
            detect_identified(Host::ClaudeCode, &path, &vars).map(|(d, _)| d.version),
            Err(DetectError::Changed)
        );
        // The replacement answers for itself afterwards.
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            detect_identified(Host::ClaudeCode, &path, &vars).map(|(d, _)| d.version),
            Ok("2.1.999".to_owned())
        );
    }

    /// The Codex review's finding: a `--version` that exits at once but
    /// leaves a process holding its output open is answered within the
    /// limit, as a timeout, never a wait for that process.
    ///
    /// Mutation checked: the readers joined after the exit (the previous
    /// `reader.join()`): the call waits for the left process (30 s) and
    /// this fails.
    #[test]
    fn a_process_left_holding_the_output_does_not_hold_the_wait() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let fake = dir.path().join("codex");
        std::fs::write(
            &fake,
            "#!/bin/sh\necho 'codex-cli 0.159.2'\nsleep 30 &\nexit 0\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut cmd = Command::new(&fake);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let t = Instant::now();
        let got = run_bounded(&mut cmd, Duration::from_secs(2), MAX_OUTPUT);
        assert_eq!(got.err(), Some(Bounded::Timeout));
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
        // A command that finishes, its output closed, is read whole.
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "echo out; echo err >&2"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let got = run_bounded(&mut cmd, Duration::from_secs(5), MAX_OUTPUT)
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            (got.stdout.as_slice(), got.stderr.as_slice()),
            (&b"out\n"[..], &b"err\n"[..])
        );
    }
}
