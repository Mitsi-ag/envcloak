//! Worker Chrome launch specification and SPEC §6.8 entry-image binding
//! (`envcloakd` driver and reaper startup anchor, task M2b-07).
//!
//! - **Worker Chrome launch (`LaunchSpec`)**: pinned Chrome for Testing with its
//!   SHA-256 verified through an open file descriptor before every launch;
//!   `--remote-debugging-pipe`; a fresh `0700` `--user-data-dir` per attempt;
//!   headless; no extensions, first run, sync or crash reporting; no listening
//!   socket (`--remote-debugging-port` refused) and no tracing, HAR, video or
//!   screenshots; cleared environment with `HOME` set to the attempt directory;
//!   only descriptors 3 and 4 inherited via [`envcloak_sys::spawn_with_fds`],
//!   returning an [`OwnedChild`]; `RLIMIT_CORE = 0`; started only by the reaper,
//!   never by the driver.
//! - **Entry-image binding (`EntryImageAnchor`)**: the daemon starts both the
//!   driver (`--signin-driver`) and reaper (`--signin-reaper`) from its own
//!   executable image as it was at startup: a sealed in-memory copy on Linux
//!   (`SealedImage` + `execveat`), or a suspended start (`POSIX_SPAWN_START_SUSPENDED`)
//!   whose `cdhash` equals the startup identity on macOS. Never reopens a path
//!   to choose those programs and never falls back to a mutable own image.

use std::fs::File;
use std::io::{self, Read};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsFd;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use envcloak_sys::launch::{Program, Session, Spawn, spawn};
use envcloak_sys::{OwnedChild, SpawnCommand, SpawnOpts, spawn_with_fds};

/// Fixed descriptor number for Chrome's `--remote-debugging-pipe` input (read by Chrome).
pub const CHROME_CDP_READ_FD: RawFd = 3;

/// Fixed descriptor number for Chrome's `--remote-debugging-pipe` output (written by Chrome).
pub const CHROME_CDP_WRITE_FD: RawFd = 4;

/// Flags forbidden in a worker [`LaunchSpec`] (`R-M2b-39`, gate `b2`: no debug
/// port, no `DevToolsActivePort`, no tracing, HAR, video or screenshot flags).
pub const FORBIDDEN_CHROME_FLAGS: &[&str] = &[
    "--remote-debugging-port",
    "--remote-debugging-address",
    "--remote-allow-origins",
    "--trace-startup",
    "--trace-to-file",
    "--log-net-log",
    "--enable-logging",
    "--v=",
    "--vmodule",
    "--screenshot",
    "--dump-dom",
    "--print-to-pdf",
    "--load-extension",
    "--ignore-certificate-errors",
];

/// Launch specification handed to the reaper for one sign-in worker attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchSpec {
    /// Unique identifier for this attempt (written into `teardown.confirmed`).
    pub attempt_id: String,
    /// Absolute path to the pinned Chrome for Testing executable.
    pub chrome_exe: PathBuf,
    /// Expected lowercase hex SHA-256 of `chrome_exe` (`64` hex digits).
    pub expected_sha256_hex: String,
    /// Absolute path to the attempt directory (`HOME` and `TMPDIR` for Chrome).
    pub attempt_dir_path: PathBuf,
    /// Relative name of the `0700` profile directory inside `attempt_dir_path`
    /// (always `"profile"`).
    pub profile_subdir: String,
    /// Optional `--host-resolver-rules` (e.g. mapping `.localhost` test hosts to `127.0.0.1`).
    pub host_resolver_rules: Option<String>,
    /// Optional driver-side loopback proxy (`127.0.0.1:<port>`) enforcing the
    /// origin guard before any socket connection leaves the worker.
    pub proxy_server: Option<String>,
    /// Optional SPKI SHA-256 base64 pin for the test CA (`--ignore-certificate-errors-spki-list`),
    /// allowed only in `testing` builds so self-signed certificates are still refused.
    pub test_ca_spki_sha256: Option<String>,
    /// Extra arguments (validated against [`FORBIDDEN_CHROME_FLAGS`]).
    pub extra_args: Vec<String>,
}

/// Reason a [`LaunchSpec`] or Chrome executable verification was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchError {
    /// A forbidden flag (such as `--remote-debugging-port` or `--ignore-certificate-errors`)
    /// was present in the launch specification.
    ForbiddenFlag(String),
    /// `profile_subdir` was not a single safe directory component.
    InvalidProfileSubdir,
    /// `chrome_exe` could not be opened as a regular file without following symlinks.
    OpenExecutable,
    /// `chrome_exe`'s SHA-256 did not match `expected_sha256_hex`.
    HashMismatch { expected: String, actual: String },
    /// `spawn_with_fds` failed to start the worker.
    SpawnFailed(String),
}

impl core::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LaunchError::ForbiddenFlag(flag) => write!(f, "forbidden_chrome_flag({flag})"),
            LaunchError::InvalidProfileSubdir => f.write_str("invalid_profile_subdir"),
            LaunchError::OpenExecutable => f.write_str("chrome_executable_open_failed"),
            LaunchError::HashMismatch { .. } => f.write_str("chrome_sha256_mismatch"),
            LaunchError::SpawnFailed(_) => f.write_str("chrome_spawn_failed"),
        }
    }
}

impl std::error::Error for LaunchError {}

impl LaunchSpec {
    /// Creates a [`LaunchSpec`] with `"profile"` as the profile subdirectory.
    pub fn new(
        attempt_id: impl Into<String>,
        chrome_exe: impl Into<PathBuf>,
        expected_sha256_hex: impl Into<String>,
        attempt_dir_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            attempt_id: attempt_id.into(),
            chrome_exe: chrome_exe.into(),
            expected_sha256_hex: expected_sha256_hex.into(),
            attempt_dir_path: attempt_dir_path.into(),
            profile_subdir: "profile".to_owned(),
            host_resolver_rules: None,
            proxy_server: None,
            test_ca_spki_sha256: None,
            extra_args: Vec::new(),
        }
    }

    /// Validates the launch specification and returns the exact argument list
    /// passed to Chrome after `argv[0]`.
    ///
    /// # Errors
    /// Returns [`LaunchError`] if `profile_subdir` is invalid or any extra flag
    /// matches [`FORBIDDEN_CHROME_FLAGS`].
    pub fn build_args(&self) -> Result<Vec<String>, LaunchError> {
        if self.profile_subdir.is_empty()
            || self.profile_subdir == "."
            || self.profile_subdir == ".."
            || self.profile_subdir.contains('/')
            || self.profile_subdir.contains('\0')
        {
            return Err(LaunchError::InvalidProfileSubdir);
        }

        for extra in &self.extra_args {
            for &forbidden in FORBIDDEN_CHROME_FLAGS {
                if extra == forbidden
                    || extra.starts_with(&format!("{forbidden}="))
                    || (forbidden.ends_with('=') && extra.starts_with(forbidden))
                {
                    return Err(LaunchError::ForbiddenFlag(extra.clone()));
                }
            }
        }

        let profile_path = self.attempt_dir_path.join(&self.profile_subdir);
        let mut args = vec![
            "--headless".to_owned(),
            "--remote-debugging-pipe".to_owned(),
            format!("--user-data-dir={}", profile_path.display()),
            "--no-first-run".to_owned(),
            "--no-default-browser-check".to_owned(),
            "--disable-extensions".to_owned(),
            "--disable-component-extensions-with-background-pages".to_owned(),
            "--disable-default-apps".to_owned(),
            "--no-service-autorun".to_owned(),
            "--disable-sync".to_owned(),
            "--disable-background-networking".to_owned(),
            "--disable-breakpad".to_owned(),
            "--disable-crash-reporter".to_owned(),
            "--disable-component-update".to_owned(),
            "--disable-domain-reliability".to_owned(),
            "--disable-client-side-phishing-detection".to_owned(),
            "--disable-features=OptimizationHints,MediaRouter,DialMediaRouteProvider,Translate,NetworkTimeServiceQuerying,AutofillServerCommunication,CertificateTransparencyComponentUpdater".to_owned(),
            "--no-pings".to_owned(),
            "-- metrics-recording-only".replace("-- ", "--"),
            "-- safebrowsing-disable-auto-update".replace("-- ", "--"),
            "-- password-store=basic".replace("-- ", "--"),
            "-- use-mock-keychain".replace("-- ", "--"),
        ];

        if let Some(rules) = &self.host_resolver_rules {
            args.push(format!("--host-resolver-rules={rules}"));
        }
        if let Some(proxy) = &self.proxy_server {
            args.push(format!("--proxy-server={proxy}"));
            // Route loopback and .localhost through the driver-side origin proxy as well.
            args.push("--proxy-bypass-list=<-loopback>".to_owned());
        }
        if let Some(spki) = &self.test_ca_spki_sha256 {
            args.push(format!("--ignore-certificate-errors-spki-list={spki}"));
        }
        args.extend(self.extra_args.iter().cloned());
        args.push("about:blank".to_owned());
        Ok(args)
    }

    /// Opens `chrome_exe` without following symlinks, verifies it is a regular
    /// file, and computes its SHA-256 through the open file descriptor, comparing
    /// against `self.expected_sha256_hex`.
    ///
    /// # Errors
    /// Returns [`LaunchError::OpenExecutable`] or [`LaunchError::HashMismatch`].
    pub fn verify_executable_sha256(&self) -> Result<File, LaunchError> {
        let file =
            open_regular_nofollow(&self.chrome_exe).map_err(|_| LaunchError::OpenExecutable)?;
        let actual = sha256_file_fd(&file).map_err(|_| LaunchError::OpenExecutable)?;
        let expected = self.expected_sha256_hex.to_ascii_lowercase();
        if actual != expected {
            return Err(LaunchError::HashMismatch { expected, actual });
        }
        Ok(file)
    }

    /// Verifies `chrome_exe`'s SHA-256 and spawns Chrome in a new session (`setsid`)
    /// with a cleared environment (`HOME` and `TMPDIR` set to `attempt_dir_path`),
    /// `RLIMIT_CORE = 0`, `PR_SET_PDEATHSIG = SIGKILL` on Linux, and only descriptors
    /// 3 (`cdp_read_fd`) and 4 (`cdp_write_fd`) inherited.
    ///
    /// # Errors
    /// Returns [`LaunchError`] if verification or spawning fails.
    pub fn spawn_worker_chrome(
        &self,
        cdp_read_fd: RawFd,
        cdp_write_fd: RawFd,
    ) -> Result<OwnedChild, LaunchError> {
        let _verified_file = self.verify_executable_sha256()?;
        let args = self.build_args()?;

        let mut cmd = SpawnCommand::new(&self.chrome_exe);
        cmd.rlimit_core_zero = true;
        cmd.args(&args);
        cmd.env("HOME", &self.attempt_dir_path);
        cmd.env("TMPDIR", &self.attempt_dir_path);
        cmd.env("PATH", "/usr/bin:/bin");
        cmd.current_dir(&self.attempt_dir_path);

        let fd_map = [
            (cdp_read_fd, CHROME_CDP_READ_FD),
            (cdp_write_fd, CHROME_CDP_WRITE_FD),
        ];
        spawn_with_fds(
            &cmd,
            &fd_map,
            SpawnOpts {
                new_session: true,
                pdeathsig: Some(9), // SIGKILL on Linux
            },
        )
        .map_err(|e| LaunchError::SpawnFailed(e.to_string()))
    }
}

fn open_regular_nofollow(path: &Path) -> io::Result<File> {
    envcloak_sys::open_regular_nofollow(path)
}

/// Computes the lowercase hex SHA-256 digest of `file` through its open file descriptor.
///
/// # Errors
/// Returns an [`io::Error`] if reading from `file` fails.
pub fn sha256_file_fd(mut file: &File) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Why an [`EntryImageAnchor`] could not be captured at startup or could not
/// start a bound driver/reaper child (`SPEC.md` §6.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryImageError {
    /// The executable file could not be opened as a regular file at startup.
    NotFound,
    /// Linux: the sealed in-memory copy (`memfd_create` + `F_ADD_SEALS`) failed.
    SealedCopyFailed,
    /// macOS: the startup executable had no valid Mach-O code directory or `cdhash`.
    Unsigned,
    /// macOS: the suspended child's kernel `cdhash` or team identity did not
    /// match the startup identity, so it was killed before resumption.
    IdentityMismatch,
    /// Spawning or resuming the bound child failed.
    SpawnFailed,
}

impl core::fmt::Display for EntryImageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EntryImageError::NotFound => f.write_str("entry_image_not_found"),
            EntryImageError::SealedCopyFailed => f.write_str("entry_image_sealed_copy_failed"),
            EntryImageError::Unsigned => f.write_str("entry_image_unsigned"),
            EntryImageError::IdentityMismatch => f.write_str("entry_image_identity_mismatch"),
            EntryImageError::SpawnFailed => f.write_str("entry_image_spawn_failed"),
        }
    }
}

impl std::error::Error for EntryImageError {}

/// Retained startup executable identity for starting `envcloakd --signin-driver`
/// and `envcloakd --signin-reaper` (`SPEC.md` §6.8, task `M2b-07`).
///
/// - On Linux: holds a [`envcloak_sys::launch::SealedImage`] (`memfd` sealed
///   with `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK`) and its SHA-256 digest,
///   and starts every driver/reaper via `execveat(fd, "", AT_EMPTY_PATH)` without
///   ever reopening a file path on disk.
/// - On macOS: holds the canonical path and the startup `cdhash`, signing
///   identifier, and team ID, starts every driver/reaper suspended
///   (`POSIX_SPAWN_START_SUSPENDED`), verifies the suspended child's `cdhash`
///   via `proc_info(child_pid)` before any user-space instruction runs, and
///   kills/reaps the child without resuming if the identity differs.
#[derive(Debug)]
pub struct EntryImageAnchor {
    inner: AnchorInner,
    sha256: [u8; 32],
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    cdhash_override_for_tests: Option<[u8; envcloak_sys::CDHASH_LEN]>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
struct AnchorInner {
    sealed: envcloak_sys::launch::SealedImage,
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[derive(Debug, Clone)]
struct AnchorInner {
    path: PathBuf,
    cdhash: [u8; envcloak_sys::CDHASH_LEN],
    identifier: Option<String>,
    team_id: Option<String>,
}

impl EntryImageAnchor {
    /// Captures the current process's own executable (`std::env::current_exe()`)
    /// at daemon startup.
    ///
    /// # Errors
    /// Returns [`EntryImageError`] if the executable cannot be opened, sealed
    /// (Linux), or code-directory-verified (macOS).
    pub fn capture_current_exe() -> Result<Self, EntryImageError> {
        let exe = std::env::current_exe().map_err(|_| EntryImageError::NotFound)?;
        let canon = std::fs::canonicalize(exe).map_err(|_| EntryImageError::NotFound)?;
        Self::capture_from_path(&canon)
    }

    /// Captures `path` as the startup entry-image anchor.
    ///
    /// # Errors
    /// Returns [`EntryImageError`] if `path` is not a regular file, cannot be
    /// copied into a sealed image on Linux, or lacks a valid code directory on
    /// macOS. Never falls back to a mutable file.
    pub fn capture_from_path(path: &Path) -> Result<Self, EntryImageError> {
        envcloak_sys::fail_point("signin.entry_image.capture")
            .map_err(|_| EntryImageError::SealedCopyFailed)?;
        let file = open_regular_nofollow(path).map_err(|_| EntryImageError::NotFound)?;
        Self::capture_from_file(path, &file)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn capture_from_file(_path: &Path, file: &File) -> Result<Self, EntryImageError> {
        let sealed = envcloak_sys::launch::SealedImage::copy_from(
            file.as_fd(),
            envcloak_sys::codesign::MAX_EXECUTABLE,
        )
        .map_err(|_| EntryImageError::SealedCopyFailed)?;

        let mut dup = file
            .try_clone()
            .map_err(|_| EntryImageError::SealedCopyFailed)?;
        use std::io::Seek;
        let _ = dup.seek(std::io::SeekFrom::Start(0));
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = dup
                .read(&mut buf)
                .map_err(|_| EntryImageError::SealedCopyFailed)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let sha256: [u8; 32] = hasher.finalize().into();
        Ok(Self {
            inner: AnchorInner { sealed },
            sha256,
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn capture_from_file(path: &Path, file: &File) -> Result<Self, EntryImageError> {
        let mut dup = file.try_clone().map_err(|_| EntryImageError::NotFound)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = dup.read(&mut buf).map_err(|_| EntryImageError::NotFound)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let sha256: [u8; 32] = hasher.finalize().into();

        let cd = envcloak_sys::codesign::code_directory(file)
            .map_err(|_| EntryImageError::Unsigned)?
            .ok_or(EntryImageError::Unsigned)?;
        let cdhash = compute_cdhash(&cd).ok_or(EntryImageError::Unsigned)?;

        Ok(Self {
            inner: AnchorInner {
                path: path.to_path_buf(),
                cdhash,
                identifier: cd.identifier,
                team_id: cd.team,
            },
            sha256,
            cdhash_override_for_tests: None,
        })
    }

    /// SHA-256 of the anchored startup image.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Overrides the expected startup `cdhash` on macOS (for deterministic
    /// negative-control testing of a suspended driver/reaper whose `cdhash`
    /// differs from the startup identity).
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub fn with_expected_cdhash_for_test(mut self, cdhash: [u8; envcloak_sys::CDHASH_LEN]) -> Self {
        self.cdhash_override_for_tests = Some(cdhash);
        self
    }

    /// Spawns a bound driver or reaper child from the retained startup image
    /// with a cleared environment (`env`), explicit `argv` and `fds`, in its own
    /// process group (`Session::Group`).
    ///
    /// Never reopens a path on Linux (executes the sealed `memfd` directly) and
    /// on macOS starts the child suspended, verifies its kernel `cdhash` before
    /// resumption, and kills + reaps it before any instruction runs if verification
    /// fails.
    ///
    /// # Errors
    /// Returns [`EntryImageError`] on verification mismatch or spawn failure.
    pub fn spawn_bound(
        &self,
        argv: &[&[u8]],
        env: &[&[u8]],
        fds: &[(BorrowedFd<'_>, i32)],
    ) -> Result<OwnedChild, EntryImageError> {
        envcloak_sys::fail_point("signin.entry_image.spawn")
            .map_err(|_| EntryImageError::SpawnFailed)?;
        self.spawn_bound_imp(argv, env, fds)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn spawn_bound_imp(
        &self,
        argv: &[&[u8]],
        env: &[&[u8]],
        fds: &[(BorrowedFd<'_>, i32)],
    ) -> Result<OwnedChild, EntryImageError> {
        spawn(&Spawn {
            program: Program::Descriptor(self.inner.sealed.as_fd()),
            argv,
            env,
            fds,
            cwd: None,
            session: Session::Group,
            suspended: false,
        })
        .map_err(|_| EntryImageError::SpawnFailed)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn spawn_bound_imp(
        &self,
        argv: &[&[u8]],
        env: &[&[u8]],
        fds: &[(BorrowedFd<'_>, i32)],
    ) -> Result<OwnedChild, EntryImageError> {
        let child = spawn(&Spawn {
            program: Program::Path(self.inner.path.as_os_str().as_bytes()),
            argv,
            env,
            fds,
            cwd: None,
            session: Session::Group,
            suspended: true,
        })
        .map_err(|_| EntryImageError::SpawnFailed)?;

        let Ok(pid) = i32::try_from(child.id()) else {
            let _ = child.kill_and_reap();
            return Err(EntryImageError::SpawnFailed);
        };
        let sig = envcloak_sys::proc_info(pid)
            .ok()
            .and_then(|p| p.exe)
            .and_then(|e| e.signature);
        let expected_cdhash = self.cdhash_override_for_tests.unwrap_or(self.inner.cdhash);
        let matches = sig.as_ref().is_some_and(|s| {
            s.cdhash == Some(expected_cdhash)
                && self
                    .inner
                    .identifier
                    .as_ref()
                    .is_none_or(|id| s.identifier.as_str() == id.as_str())
                && s.team_id == self.inner.team_id
        });
        if !matches {
            let _ = child.kill_and_reap();
            return Err(EntryImageError::IdentityMismatch);
        }
        if child.resume().is_err() {
            let _ = child.kill_and_reap();
            return Err(EntryImageError::SpawnFailed);
        }
        Ok(child)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn compute_cdhash(
    cd: &envcloak_sys::codesign::CodeDirectory,
) -> Option<[u8; envcloak_sys::CDHASH_LEN]> {
    let digest: Vec<u8> = match cd.hash_type {
        // CS_HASHTYPE_SHA256 (2) or CS_HASHTYPE_SHA256_TRUNCATED (3)
        2 | 3 => Sha256::digest(cd.cdhash_input()).to_vec(),
        _ => return None,
    };
    digest.get(..envcloak_sys::CDHASH_LEN)?.try_into().ok()
}

#[allow(dead_code)]
fn _assert_raw_fd_used(fd: &File) -> RawFd {
    fd.as_raw_fd()
}
