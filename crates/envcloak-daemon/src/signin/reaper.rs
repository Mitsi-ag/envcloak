//! Isolated sign-in worker reaper process (`envcloakd --signin-reaper`,
//! SPEC §6.8, M2 plan D-34, F-73, CR-3, gate `b12`, task `M2b-09`).
//!
//! Started per attempt from the daemon's retained startup image
//! ([`EntryImageAnchor`]) with a cleared environment and only the control
//! socketpair (descriptor 3), the lifeline pipe read end (descriptor 4), and
//! Chrome's CDP pipes (descriptors 5 and 6). Owns the worker Chrome
//! [`OwnedChild`] handle, parses no page-influenced data, holds no secret, and
//! writes `teardown.confirmed` with `O_EXCL` only after the full teardown
//! sequence completes.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use envcloak_browser::{
    EntryImageAnchor, LaunchSpec, REAPER_COMMAND_BYTES, REAPER_LOCK_FILE, REAPER_REPLY_BYTES,
    Reaper, ReaperCommand, ReaperReply, TEARDOWN_CONFIRMATION_FILE, TeardownRecord, TeardownStep,
};
use envcloak_sys::fdpass::{DescriptorKind, descriptor_kind};
use envcloak_sys::{
    OwnedChild, create_dir_beneath, create_rw_beneath, fail_point, kind_beneath, open_beneath,
    reap_reparented_children, remove_tree_beneath_and_verify, set_child_subreaper,
    take_inherited_fd, try_lock_exclusive, wait_any,
};

/// Inherited descriptor for the daemon <-> reaper control socketpair.
pub const REAPER_CONTROL_FD: i32 = 3;
/// Inherited descriptor for the read end of the attempt lifeline pipe.
pub const REAPER_LIFELINE_FD: i32 = 4;
/// Inherited descriptor for the read end of Chrome's CDP input pipe.
pub const REAPER_CDP_READ_FD: i32 = 5;
/// Inherited descriptor for the write end of Chrome's CDP output pipe.
pub const REAPER_CDP_WRITE_FD: i32 = 6;

/// Private environment variable carrying the spawning daemon's PID.
pub const REAPER_PARENT_ENV: &str = "ENVCLOAKD_SIGNIN_PARENT_PID";

const MAX_BOOTSTRAP_BYTES: usize = 64 * 1024;

/// Initial bootstrap message sent from the daemon to `envcloakd --signin-reaper`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaperBootstrap {
    pub launch: LaunchSpec,
}

/// Validates that the current process was started by `envcloakd` with the
/// private reaper descriptor layout (`fd 3` UnixStream socketpair whose peer
/// PID matches `getppid()`, `fd 4` lifeline pipe, `fd 5` and `fd 6` CDP pipes)
/// and returns those owned descriptors.
fn take_daemon_descriptors() -> Result<(UnixStream, OwnedFd, OwnedFd, OwnedFd), &'static str> {
    let expected_ppid_str =
        std::env::var(REAPER_PARENT_ENV).map_err(|_| "missing parent pid env")?;
    let expected_ppid: i32 = expected_ppid_str
        .parse()
        .map_err(|_| "invalid parent pid env")?;
    let actual_ppid =
        i32::try_from(std::os::unix::process::parent_id()).map_err(|_| "invalid parent pid")?;
    if expected_ppid <= 1 || expected_ppid != actual_ppid {
        return Err("parent pid mismatch");
    }

    let ctrl_fd = take_inherited_fd(REAPER_CONTROL_FD).map_err(|_| "missing descriptor 3")?;
    let (ctrl_kind, _) = descriptor_kind(ctrl_fd.as_fd()).map_err(|_| "invalid descriptor 3")?;
    if ctrl_kind != DescriptorKind::Socket {
        return Err("descriptor 3 is not a socket");
    }
    let peer = envcloak_sys::peer_identity(ctrl_fd.as_fd()).map_err(|_| "peer_identity failed")?;
    if peer.pid != expected_ppid {
        return Err("control socket peer pid mismatch");
    }

    let lifeline = take_inherited_fd(REAPER_LIFELINE_FD).map_err(|_| "missing descriptor 4")?;
    let cdp_read = take_inherited_fd(REAPER_CDP_READ_FD).map_err(|_| "missing descriptor 5")?;
    let cdp_write = take_inherited_fd(REAPER_CDP_WRITE_FD).map_err(|_| "missing descriptor 6")?;

    for fd in [&lifeline, &cdp_read, &cdp_write] {
        match descriptor_kind(fd.as_fd()) {
            Ok((DescriptorKind::Pipe | DescriptorKind::Socket, _)) => {}
            _ => return Err("reaper pipe descriptor invalid"),
        }
    }

    Ok((UnixStream::from(ctrl_fd), lifeline, cdp_read, cdp_write))
}

/// Writes a length-prefixed JSON bootstrap frame to the reaper control stream.
pub fn write_bootstrap<W: Write>(mut writer: W, msg: &ReaperBootstrap) -> io::Result<()> {
    let payload =
        serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if payload.len() > MAX_BOOTSTRAP_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reaper bootstrap frame exceeds limit",
        ));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

/// Reads a length-prefixed JSON bootstrap frame from the reaper control stream.
pub fn read_bootstrap<R: Read>(mut reader: R) -> io::Result<ReaperBootstrap> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 || len > MAX_BOOTSTRAP_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid reaper bootstrap length",
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Opens `path` as a directory handle without following a terminal symlink on
/// the final component when opened beneath its parent.
pub fn open_attempt_dir(path: &Path) -> io::Result<File> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "attempt dir has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "attempt dir has no name"))?;
    let parent_file = File::open(parent)?;
    envcloak_sys::open_dir_beneath(&parent_file, name)
}

/// Entry point for `envcloakd --signin-reaper`.
///
/// Refuses direct invocation with exit code `125` and reason
/// `not_started_by_daemon`.
pub fn main() -> ExitCode {
    let (mut ctrl_stream, lifeline, cdp_read, cdp_write) = match take_daemon_descriptors() {
        Ok(fds) => fds,
        Err(reason) => {
            let _ = writeln!(
                io::stderr(),
                "envcloak: not_started_by_daemon: --signin-reaper may only be started by envcloakd ({reason})"
            );
            return ExitCode::from(125);
        }
    };

    let bootstrap = match read_bootstrap(&mut ctrl_stream) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(io::stderr(), "envcloak: signin-reaper bootstrap error: {e}");
            return ExitCode::from(2);
        }
    };

    let Ok(ctrl_write) = ctrl_stream.try_clone() else {
        return ExitCode::from(2);
    };

    let attempt_dir_file = match open_attempt_dir(&bootstrap.launch.attempt_dir_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = writeln!(
                io::stderr(),
                "envcloak: signin-reaper attempt dir open failed: {e}"
            );
            return ExitCode::from(2);
        }
    };
    let _ = create_dir_beneath(
        &attempt_dir_file,
        OsStr::new(&bootstrap.launch.profile_subdir),
        0o700,
    );

    if fail_point("signin.reaper.exit_0_without_record").is_err() {
        return run_exit_0_without_record(
            ctrl_stream,
            ctrl_write,
            lifeline,
            bootstrap.launch,
            (cdp_read, cdp_write),
            attempt_dir_file,
        );
    }

    let attempt_id = bootstrap.launch.attempt_id.clone();
    let attempt_dir_fd = OwnedFd::from(attempt_dir_file);
    let outcome = Reaper::run(
        ctrl_stream,
        ctrl_write,
        lifeline,
        bootstrap.launch,
        (cdp_read, cdp_write),
        attempt_dir_fd,
        &attempt_id,
    );

    let code = u8::try_from(outcome.exit_code()).unwrap_or(1);
    ExitCode::from(code)
}

/// Fault-injected reaper execution (`signin.reaper.exit_0_without_record`)
/// used to test `CR-3`: tears down the worker and releases `reaper.lock`,
/// replies `ReaperReply::Confirmed`, and exits `0` without writing
/// `teardown.confirmed`.
fn run_exit_0_without_record(
    mut control_r: UnixStream,
    mut control_w: UnixStream,
    lifeline: OwnedFd,
    spec: LaunchSpec,
    cdp_fds: (OwnedFd, OwnedFd),
    attempt_dir_file: File,
) -> ExitCode {
    let Ok(lock_file) = create_rw_beneath(&attempt_dir_file, OsStr::new(REAPER_LOCK_FILE), 0o600)
    else {
        return ExitCode::from(1);
    };
    if !try_lock_exclusive(&lock_file).unwrap_or(false) {
        return ExitCode::from(1);
    }
    let _ = set_child_subreaper();

    let (cdp_in_fd, cdp_out_fd) = cdp_fds;
    let maybe_child = spec
        .spawn_worker_chrome(cdp_in_fd.as_raw_fd(), cdp_out_fd.as_raw_fd())
        .ok();
    drop(cdp_in_fd);
    drop(cdp_out_fd);

    loop {
        if let Some(child) = &maybe_child
            && child.has_exited().unwrap_or(true)
        {
            break;
        }
        let ready = match wait_any(
            &[
                (Some(lifeline.as_fd()), true, false),
                (Some(control_r.as_fd()), true, false),
            ],
            Some(Duration::from_millis(25)),
        ) {
            Ok(r) => r,
            Err(_) => break,
        };
        if ready[0].any() {
            break;
        }
        if ready[1].any() {
            if !ready[1].readable && (ready[1].hung_up || ready[1].failed) {
                break;
            }
            let mut frame = [0u8; REAPER_COMMAND_BYTES];
            if control_r.read_exact(&mut frame).is_err() {
                break;
            }
            match ReaperCommand::decode(&frame) {
                Ok(ReaperCommand::Stop) => break,
                Ok(ReaperCommand::Status) => {
                    let _ = control_w.write_all(&ReaperReply::Running.encode());
                    let _ = control_w.flush();
                }
                Err(_) => break,
            }
        }
    }

    if let Some(child) = maybe_child {
        let _ = child.has_exited();
        let _ = child.signal_group_before_reap(9);
        let _ = child.reap();
        let _ = reap_reparented_children(Duration::from_millis(100));
    }
    let _ = remove_tree_beneath_and_verify(&attempt_dir_file, OsStr::new("profile"));
    // Deliberately omit writing `teardown.confirmed` while claiming `Confirmed` and exiting `0`.
    let _ = control_w.write_all(&ReaperReply::Confirmed.encode());
    let _ = control_w.flush();
    ExitCode::SUCCESS
}

/// Verifies that `attempt_dir` contains a valid `teardown.confirmed` record for
/// `expected_attempt_id` and that `profile/` has been removed (`D-34`, `CR-3`).
///
/// Both active teardown and startup sweep rely on this check as the sole proof
/// of confirmed cleanup; a `0` exit status or an unlocked `reaper.lock`
/// without a valid record is never treated as confirmed.
pub fn verify_teardown_record_at(
    attempt_dir: &Path,
    expected_attempt_id: &str,
) -> Result<TeardownRecord, &'static str> {
    let dir_file = open_attempt_dir(attempt_dir).map_err(|_| "open attempt dir failed")?;

    // Profile directory must no longer exist.
    match kind_beneath(&dir_file, OsStr::new("profile")) {
        Ok(_) => return Err("profile directory still exists"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("failed to verify profile removal"),
    }

    let mut confirm_file = open_beneath(&dir_file, OsStr::new(TEARDOWN_CONFIRMATION_FILE))
        .map_err(|_| "teardown.confirmed missing")?;

    let mut bytes = Vec::new();
    confirm_file
        .read_to_end(&mut bytes)
        .map_err(|_| "read teardown.confirmed failed")?;
    let record: TeardownRecord =
        serde_json::from_slice(&bytes).map_err(|_| "invalid teardown.confirmed json")?;

    if record.attempt_id != expected_attempt_id {
        return Err("teardown.confirmed attempt_id mismatch");
    }
    let expected_steps = [
        TeardownStep::ObserveExit,
        TeardownStep::SignalGroup,
        TeardownStep::ReapLeader,
        TeardownStep::RemoveProfile,
        TeardownStep::WriteConfirmation,
    ];
    if record.steps != expected_steps {
        return Err("teardown.confirmed steps incomplete");
    }

    Ok(record)
}

/// Daemon-side handle to a running `envcloakd --signin-reaper` process.
#[derive(Debug)]
pub struct ReaperSession {
    pub child: OwnedChild,
    pub control: UnixStream,
    pub attempt_dir: PathBuf,
    pub attempt_id: String,
}

impl ReaperSession {
    /// Sends `ReaperCommand::Stop`, waits for the reaper process to exit, and
    /// returns `true` iff `verify_teardown_record_at` confirms on-disk cleanup
    /// (`CR-3`).
    pub fn stop_and_verify(self) -> bool {
        let Self {
            child,
            mut control,
            attempt_dir,
            attempt_id,
        } = self;

        let _ = control.set_write_timeout(Some(Duration::from_secs(5)));
        let _ = control.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = control.write_all(&ReaperCommand::Stop.encode());
        let _ = control.flush();

        let mut reply_buf = [0u8; REAPER_REPLY_BYTES];
        let _ = control.read_exact(&mut reply_buf);
        drop(control);

        let _ = child.reap();

        verify_teardown_record_at(&attempt_dir, &attempt_id).is_ok()
    }
}

/// Spawns `envcloakd --signin-reaper` from the daemon's [`EntryImageAnchor`],
/// sends [`ReaperBootstrap`], and returns the [`ReaperSession`].
pub fn spawn_reaper(
    anchor: &EntryImageAnchor,
    launch: LaunchSpec,
    lifeline_r: OwnedFd,
    cdp_in_r: OwnedFd,
    cdp_out_w: OwnedFd,
) -> io::Result<ReaperSession> {
    let (mut daemon_sock, reaper_sock) = UnixStream::pair()?;
    daemon_sock.set_read_timeout(Some(Duration::from_secs(15)))?;
    daemon_sock.set_write_timeout(Some(Duration::from_secs(15)))?;

    let parent_pid = std::process::id();
    let parent_env = format!("{REAPER_PARENT_ENV}={parent_pid}");
    let mut env_entries: Vec<Vec<u8>> = vec![
        parent_env.into_bytes(),
        b"PATH=/usr/bin:/bin".to_vec(),
        b"LANG=C".to_vec(),
    ];
    for (k, v) in envcloak_sys::test_hook_vars() {
        let mut entry = k.into_encoded_bytes();
        entry.push(b'=');
        entry.extend_from_slice(&v.into_encoded_bytes());
        env_entries.push(entry);
    }
    let env_slices: Vec<&[u8]> = env_entries.iter().map(Vec::as_slice).collect();
    let argv: &[&[u8]] = &[b"envcloakd", b"--signin-reaper"];
    let fds = [
        (reaper_sock.as_fd(), REAPER_CONTROL_FD),
        (lifeline_r.as_fd(), REAPER_LIFELINE_FD),
        (cdp_in_r.as_fd(), REAPER_CDP_READ_FD),
        (cdp_out_w.as_fd(), REAPER_CDP_WRITE_FD),
    ];

    let child = anchor
        .spawn_bound(argv, &env_slices, &fds)
        .map_err(|e| io::Error::other(e.to_string()))?;

    drop(reaper_sock);
    drop(lifeline_r);
    drop(cdp_in_r);
    drop(cdp_out_w);

    let attempt_dir = launch.attempt_dir_path.clone();
    let attempt_id = launch.attempt_id.clone();
    let bootstrap = ReaperBootstrap { launch };
    if let Err(e) = write_bootstrap(&mut daemon_sock, &bootstrap) {
        let _ = child.kill_and_reap();
        return Err(e);
    }

    Ok(ReaperSession {
        child,
        control: daemon_sock,
        attempt_dir,
        attempt_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn reaper_bootstrap_round_trips() {
        let launch = LaunchSpec::new(
            "att-001",
            "/opt/chrome/chrome",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "/tmp/envcloak/signin/attempts/att-001",
        );
        let bootstrap = ReaperBootstrap { launch };
        let (mut a, mut b) = UnixStream::pair().expect("pair");
        write_bootstrap(&mut a, &bootstrap).expect("write");
        let decoded = read_bootstrap(&mut b).expect("read");
        assert_eq!(decoded, bootstrap);
    }

    #[test]
    fn verify_teardown_record_rejects_missing_or_incomplete_or_remaining_profile() {
        let tmp = TempDir::new().expect("tempdir");
        let attempt_dir = tmp.path();

        // Missing teardown.confirmed is rejected.
        assert!(verify_teardown_record_at(attempt_dir, "att-1").is_err());

        // Write valid teardown.confirmed.
        let record = TeardownRecord {
            attempt_id: "att-1".to_owned(),
            steps: vec![
                TeardownStep::ObserveExit,
                TeardownStep::SignalGroup,
                TeardownStep::ReapLeader,
                TeardownStep::RemoveProfile,
                TeardownStep::WriteConfirmation,
            ],
        };
        std::fs::write(
            attempt_dir.join(TEARDOWN_CONFIRMATION_FILE),
            serde_json::to_vec(&record).expect("json"),
        )
        .expect("write");

        // Valid when profile/ is gone and attempt_id matches.
        assert_eq!(
            verify_teardown_record_at(attempt_dir, "att-1").expect("valid"),
            record
        );

        // Wrong attempt_id is rejected.
        assert!(verify_teardown_record_at(attempt_dir, "att-2").is_err());

        // Remaining profile/ directory causes rejection even when teardown.confirmed exists.
        std::fs::create_dir(attempt_dir.join("profile")).expect("mkdir profile");
        assert!(verify_teardown_record_at(attempt_dir, "att-1").is_err());
    }
}
