//! Sign-in worker reaper (`SPEC.md` §6.8, M2 plan D-34, F-73, CR-3, gate `b12`,
//! task `M2b-07`).
//!
//! Single-threaded process (`envcloakd --signin-reaper`) that owns the worker
//! Chrome child handle (`OwnedChild`), parses no page input, holds no secret
//! value, and enforces the strict teardown sequence:
//! 1. Acquire an exclusive `flock` on `reaper.lock` inside `attempt_dir`.
//! 2. Enable `PR_SET_CHILD_SUBREAPER` on Linux (`set_child_subreaper`).
//! 3. Verify Chrome's SHA-256 through an open file descriptor and spawn Chrome
//!    in its own session (`setsid`, `PR_SET_PDEATHSIG = SIGKILL` on Linux,
//!    `RLIMIT_CORE = 0`, descriptors `3` and `4` mapped to the CDP pipes).
//! 4. Wait for `ReaperCommand::Stop` on the control pipe, EOF on `lifeline`, or
//!    Chrome's own exit.
//! 5. Execute the strict cleanup order:
//!    - Observe exit without reaping (`OwnedChild::has_exited`).
//!    - Signal Chrome's process group while the leader is still unreaped
//!      (`OwnedChild::signal_group_before_reap(SIGKILL)`).
//!    - Reap Chrome (`OwnedChild::reap`) and any reparented descendants
//!      (`reap_reparented_children`).
//!    - Remove `profile` beneath `attempt_dir` without following symlinks and
//!      verify that `profile` is gone (`remove_tree_beneath_and_verify`).
//!    - Create `teardown.confirmed` with `O_EXCL` beneath `attempt_dir`, write
//!      [`TeardownRecord`], `fsync` the file, and `fsync` `attempt_dir`.
//!    - Release `reaper.lock` and exit `0` only if every step succeeded.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use envcloak_sys::{
    OwnedChild, ProcessOps, create_beneath, create_rw_beneath, fail_point,
    reap_reparented_children, remove_tree_beneath_and_verify, set_child_subreaper, sync_file,
    try_lock_exclusive, wait_any,
};

use crate::launch::LaunchSpec;

const SIGKILL_SIGNAL: i32 = 9;

/// File name of the exclusive reaper lock inside the attempt directory.
pub const REAPER_LOCK_FILE: &str = "reaper.lock";

/// File name of the `O_EXCL` teardown confirmation record inside the attempt directory.
pub const TEARDOWN_CONFIRMATION_FILE: &str = "teardown.confirmed";

/// File name of the non-authoritative diagnostic metadata written for test inspection.
pub const WORKER_DIAGNOSTIC_FILE: &str = "worker.meta.json";

/// Fixed byte length of a [`ReaperCommand`] frame on the control pipe.
pub const REAPER_COMMAND_BYTES: usize = 8;

/// Fixed byte length of a [`ReaperReply`] frame on the control pipe.
pub const REAPER_REPLY_BYTES: usize = 8;

const CMD_MAGIC: [u8; 4] = *b"ECRP";
const REPLY_MAGIC: [u8; 4] = *b"ECRR";
const PROTO_VERSION: u8 = 1;

/// Fixed-size control message sent from the daemon to the reaper (`M2b-07`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaperCommand {
    /// Tear down the worker Chrome process group, remove the profile, and confirm.
    Stop,
    /// Query whether the reaper is still running.
    Status,
}

/// Error decoding a fixed-size [`ReaperCommand`] or [`ReaperReply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlDecodeError {
    InvalidMagic,
    UnsupportedVersion,
    UnknownOpcode,
    NonZeroReserved,
}

impl ReaperCommand {
    /// Encodes `self` into an 8-byte fixed-size frame.
    pub const fn encode(self) -> [u8; REAPER_COMMAND_BYTES] {
        let op = match self {
            ReaperCommand::Stop => 1u8,
            ReaperCommand::Status => 2u8,
        };
        [
            CMD_MAGIC[0],
            CMD_MAGIC[1],
            CMD_MAGIC[2],
            CMD_MAGIC[3],
            PROTO_VERSION,
            op,
            0,
            0,
        ]
    }

    /// Decodes an 8-byte fixed-size frame into a [`ReaperCommand`].
    ///
    /// # Errors
    /// Returns [`ControlDecodeError`] if the magic, version, opcode, or reserved
    /// bytes are invalid.
    pub fn decode(bytes: &[u8; REAPER_COMMAND_BYTES]) -> Result<Self, ControlDecodeError> {
        if bytes[0..4] != CMD_MAGIC {
            return Err(ControlDecodeError::InvalidMagic);
        }
        if bytes[4] != PROTO_VERSION {
            return Err(ControlDecodeError::UnsupportedVersion);
        }
        if bytes[6] != 0 || bytes[7] != 0 {
            return Err(ControlDecodeError::NonZeroReserved);
        }
        match bytes[5] {
            1 => Ok(ReaperCommand::Stop),
            2 => Ok(ReaperCommand::Status),
            _ => Err(ControlDecodeError::UnknownOpcode),
        }
    }
}

/// Step of the reaper lifecycle or teardown sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeardownStep {
    /// Acquire `reaper.lock` or verify/launch the Chrome binary.
    Launch,
    /// Observe worker exit status without reaping (`has_exited`).
    ObserveExit,
    /// Signal Chrome's process group while the leader is still unreaped (`signal_group_before_reap`).
    SignalGroup,
    /// Reap the Chrome session leader and any reparented descendants (`reap`).
    ReapLeader,
    /// Remove the `profile` directory through the directory descriptor without following links and verify it is gone.
    RemoveProfile,
    /// Write `teardown.confirmed` with `O_EXCL` and `fsync` file + directory.
    WriteConfirmation,
}

impl TeardownStep {
    pub const fn code(self) -> u8 {
        match self {
            TeardownStep::Launch => 1,
            TeardownStep::ObserveExit => 2,
            TeardownStep::SignalGroup => 3,
            TeardownStep::ReapLeader => 4,
            TeardownStep::RemoveProfile => 5,
            TeardownStep::WriteConfirmation => 6,
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(TeardownStep::Launch),
            2 => Some(TeardownStep::ObserveExit),
            3 => Some(TeardownStep::SignalGroup),
            4 => Some(TeardownStep::ReapLeader),
            5 => Some(TeardownStep::RemoveProfile),
            6 => Some(TeardownStep::WriteConfirmation),
            _ => None,
        }
    }
}

/// Fixed-size reply sent from the reaper to the daemon on the control pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaperReply {
    /// Worker is still running.
    Running,
    /// Teardown completed and `teardown.confirmed` is on disk.
    Confirmed,
    /// Teardown failed at the specified [`TeardownStep`].
    Failed(TeardownStep),
}

impl ReaperReply {
    /// Encodes `self` into an 8-byte fixed-size frame.
    pub const fn encode(self) -> [u8; REAPER_REPLY_BYTES] {
        let (status, step) = match self {
            ReaperReply::Running => (1u8, 0u8),
            ReaperReply::Confirmed => (2u8, 0u8),
            ReaperReply::Failed(s) => (3u8, s.code()),
        };
        [
            REPLY_MAGIC[0],
            REPLY_MAGIC[1],
            REPLY_MAGIC[2],
            REPLY_MAGIC[3],
            PROTO_VERSION,
            status,
            step,
            0,
        ]
    }

    /// Decodes an 8-byte fixed-size frame into a [`ReaperReply`].
    ///
    /// # Errors
    /// Returns [`ControlDecodeError`] if the frame is malformed.
    pub fn decode(bytes: &[u8; REAPER_REPLY_BYTES]) -> Result<Self, ControlDecodeError> {
        if bytes[0..4] != REPLY_MAGIC {
            return Err(ControlDecodeError::InvalidMagic);
        }
        if bytes[4] != PROTO_VERSION {
            return Err(ControlDecodeError::UnsupportedVersion);
        }
        if bytes[7] != 0 {
            return Err(ControlDecodeError::NonZeroReserved);
        }
        match (bytes[5], bytes[6]) {
            (1, 0) => Ok(ReaperReply::Running),
            (2, 0) => Ok(ReaperReply::Confirmed),
            (3, code) => TeardownStep::from_code(code)
                .map(ReaperReply::Failed)
                .ok_or(ControlDecodeError::UnknownOpcode),
            _ => Err(ControlDecodeError::UnknownOpcode),
        }
    }
}

/// On-disk teardown confirmation record (`teardown.confirmed`, `D-34`, `CR-3`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeardownRecord {
    pub attempt_id: String,
    pub steps: Vec<TeardownStep>,
}

/// Outcome of the reaper's cleanup sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupOutcome {
    /// Every teardown step succeeded and `teardown.confirmed` was written with
    /// `O_EXCL` and `fsync`ed.
    Confirmed(TeardownRecord),
    /// A launch or teardown step failed; no `teardown.confirmed` file was written.
    Failed(TeardownStep),
}

/// Final outcome returned by [`Reaper::run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaperOutcome {
    pub cleanup: CleanupOutcome,
}

impl ReaperOutcome {
    /// Exit code for `envcloakd --signin-reaper`: `0` iff [`CleanupOutcome::Confirmed`].
    pub const fn exit_code(&self) -> i32 {
        match self.cleanup {
            CleanupOutcome::Confirmed(_) => 0,
            CleanupOutcome::Failed(_) => 1,
        }
    }
}

/// Executes the strict teardown sequence on an owned `child` and `attempt_dir_file`
/// (parameterized over `P: ProcessOps` so unit and integration tests can run
/// with both [`SystemProcesses`] and [`envcloak_sys::RecordingProcesses`]).
///
/// Order enforced:
/// 1. `child.has_exited()` (observe without reaping)
/// 2. `child.signal_group_before_reap(SIGKILL)` (signal group while leader is unreaped)
/// 3. `child.reap()` + `reap_children` (reap leader and reparented children)
/// 4. `remove_tree_beneath_and_verify(attempt_dir_file, "profile")`
/// 5. `create_beneath(attempt_dir_file, "teardown.confirmed", 0o600)` (`O_EXCL`) + `sync_file`
pub fn execute_teardown_sequence<P: ProcessOps>(
    child: OwnedChild<P>,
    attempt_dir_file: &File,
    attempt_id: &str,
    reap_subreaper_children: bool,
) -> CleanupOutcome {
    let mut completed_steps = Vec::with_capacity(5);

    // Step 1: Observe exit without reaping.
    if child.has_exited().is_err() {
        return CleanupOutcome::Failed(TeardownStep::ObserveExit);
    }
    completed_steps.push(TeardownStep::ObserveExit);

    // Step 2: Signal the worker process group while the leader is still unreaped.
    if child.signal_group_before_reap(SIGKILL_SIGNAL).is_err() {
        return CleanupOutcome::Failed(TeardownStep::SignalGroup);
    }
    completed_steps.push(TeardownStep::SignalGroup);

    // Step 3: Reap the leader through the owned handle and reap any reparented descendants.
    if child.reap().is_err() {
        return CleanupOutcome::Failed(TeardownStep::ReapLeader);
    }
    if reap_subreaper_children {
        let _ = reap_reparented_children(Duration::from_millis(250));
    }
    completed_steps.push(TeardownStep::ReapLeader);

    // Step 4: Remove `profile` beneath `attempt_dir_file` without following symlinks
    // and verify that it is gone.
    if fail_point("signin.reaper.remove_profile").is_err() {
        return CleanupOutcome::Failed(TeardownStep::RemoveProfile);
    }
    if remove_tree_beneath_and_verify(attempt_dir_file, OsStr::new("profile")).is_err() {
        return CleanupOutcome::Failed(TeardownStep::RemoveProfile);
    }
    completed_steps.push(TeardownStep::RemoveProfile);

    // Step 5: Write `teardown.confirmed` with `O_EXCL`, fsync file, and fsync directory.
    if fail_point("signin.reaper.write_confirmation").is_err() {
        return CleanupOutcome::Failed(TeardownStep::WriteConfirmation);
    }
    completed_steps.push(TeardownStep::WriteConfirmation);
    let record = TeardownRecord {
        attempt_id: attempt_id.to_owned(),
        steps: completed_steps,
    };
    let Ok(payload) = serde_json::to_vec(&record) else {
        return CleanupOutcome::Failed(TeardownStep::WriteConfirmation);
    };
    let Ok(mut confirm_file) = create_beneath(
        attempt_dir_file,
        OsStr::new(TEARDOWN_CONFIRMATION_FILE),
        0o600,
    ) else {
        return CleanupOutcome::Failed(TeardownStep::WriteConfirmation);
    };
    if confirm_file.write_all(&payload).is_err() {
        return CleanupOutcome::Failed(TeardownStep::WriteConfirmation);
    }
    if sync_file(&confirm_file).is_err() {
        return CleanupOutcome::Failed(TeardownStep::WriteConfirmation);
    }
    drop(confirm_file);
    if sync_file(attempt_dir_file).is_err() {
        return CleanupOutcome::Failed(TeardownStep::WriteConfirmation);
    }

    CleanupOutcome::Confirmed(record)
}

/// Sign-in worker reaper (`envcloakd --signin-reaper`).
#[derive(Debug, Default)]
pub struct Reaper;

impl Reaper {
    /// Runs the reaper lifecycle for a single sign-in attempt.
    ///
    /// - Acquires an exclusive `flock` on `reaper.lock` in `attempt_dir`.
    /// - Sets `PR_SET_CHILD_SUBREAPER` on Linux.
    /// - Verifies Chrome's SHA-256 through an open file descriptor and spawns
    ///   Chrome as an [`OwnedChild<RealProcesses>`] in its own session.
    /// - Closes `cdp_fds` in the reaper immediately after spawning Chrome.
    /// - Waits for `ReaperCommand::Stop` on `control_r`, EOF on `lifeline`, or
    ///   Chrome's exit, then runs [`execute_teardown_sequence`], replies on
    ///   `control_w`, releases `reaper.lock`, and returns [`ReaperOutcome`].
    pub fn run<CR: Read + AsFd + Send + 'static, CW: Write>(
        mut control_r: CR,
        mut control_w: CW,
        lifeline: OwnedFd,
        spec: LaunchSpec,
        cdp_fds: (OwnedFd, OwnedFd),
        attempt_dir: OwnedFd,
        attempt_id: &str,
    ) -> ReaperOutcome {
        let attempt_dir_file = File::from(attempt_dir);

        // 1. Acquire exclusive flock on `reaper.lock` beneath `attempt_dir`.
        let Ok(lock_file) =
            create_rw_beneath(&attempt_dir_file, OsStr::new(REAPER_LOCK_FILE), 0o600)
        else {
            let _ = control_w.write_all(&ReaperReply::Failed(TeardownStep::Launch).encode());
            let _ = control_w.flush();
            return ReaperOutcome {
                cleanup: CleanupOutcome::Failed(TeardownStep::Launch),
            };
        };
        if !try_lock_exclusive(&lock_file).unwrap_or(false) {
            let _ = control_w.write_all(&ReaperReply::Failed(TeardownStep::Launch).encode());
            let _ = control_w.flush();
            return ReaperOutcome {
                cleanup: CleanupOutcome::Failed(TeardownStep::Launch),
            };
        }

        // 2. Enable subreaper on Linux so reparented worker descendants can be reaped.
        if set_child_subreaper().is_err() {
            let _ = control_w.write_all(&ReaperReply::Failed(TeardownStep::Launch).encode());
            let _ = control_w.flush();
            return ReaperOutcome {
                cleanup: CleanupOutcome::Failed(TeardownStep::Launch),
            };
        }

        // 3. Verify Chrome SHA-256 through an open fd and launch Chrome in a new session.
        let (cdp_in_fd, cdp_out_fd) = cdp_fds;
        let child = match spec.spawn_worker_chrome(cdp_in_fd.as_raw_fd(), cdp_out_fd.as_raw_fd()) {
            Ok(c) => c,
            Err(_) => {
                drop(cdp_in_fd);
                drop(cdp_out_fd);
                let _ = control_w.write_all(&ReaperReply::Failed(TeardownStep::Launch).encode());
                let _ = control_w.flush();
                return ReaperOutcome {
                    cleanup: CleanupOutcome::Failed(TeardownStep::Launch),
                };
            }
        };

        // Close the reaper's copies of the browser CDP descriptors immediately.
        drop(cdp_in_fd);
        drop(cdp_out_fd);

        // Write non-authoritative diagnostic metadata (`worker.meta.json`) so
        // tests can inspect `pid` and `sid` (`getsid(pid) == pid`) without the
        // daemon or reaper ever reading a PID from disk.
        write_worker_diagnostic(&attempt_dir_file, &child);

        // 4. Single-threaded poll on lifeline EOF and control messages while checking `child.has_exited()`.
        loop {
            if child.has_exited().unwrap_or(true) {
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
        drop(lifeline);
        drop(control_r);

        // 5. Execute strict teardown sequence.
        let cleanup = execute_teardown_sequence(child, &attempt_dir_file, attempt_id, true);
        let reply = match &cleanup {
            CleanupOutcome::Confirmed(_) => ReaperReply::Confirmed,
            CleanupOutcome::Failed(step) => ReaperReply::Failed(*step),
        };
        let _ = control_w.write_all(&reply.encode());
        let _ = control_w.flush();

        // 6. Release `_flock` on drop and return outcome.
        ReaperOutcome { cleanup }
    }
}

fn write_worker_diagnostic<P: ProcessOps>(attempt_dir_file: &File, child: &OwnedChild<P>) {
    let pid = child.id();
    let sid = child.session_id().unwrap_or(0);
    let json_bytes = serde_json::to_vec(&serde_json::json!({
        "pid": pid,
        "sid": sid,
    }))
    .unwrap_or_default();
    if let Ok(mut f) =
        create_rw_beneath(attempt_dir_file, OsStr::new(WORKER_DIAGNOSTIC_FILE), 0o600)
    {
        let _ = f.write_all(&json_bytes);
        let _ = sync_file(&f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn control_frames_round_trip_and_reject_invalid() {
        for cmd in [ReaperCommand::Stop, ReaperCommand::Status] {
            let encoded = cmd.encode();
            assert_eq!(ReaperCommand::decode(&encoded), Ok(cmd));
        }
        for reply in [
            ReaperReply::Running,
            ReaperReply::Confirmed,
            ReaperReply::Failed(TeardownStep::Launch),
            ReaperReply::Failed(TeardownStep::ObserveExit),
            ReaperReply::Failed(TeardownStep::SignalGroup),
            ReaperReply::Failed(TeardownStep::ReapLeader),
            ReaperReply::Failed(TeardownStep::RemoveProfile),
            ReaperReply::Failed(TeardownStep::WriteConfirmation),
        ] {
            let encoded = reply.encode();
            assert_eq!(ReaperReply::decode(&encoded), Ok(reply));
        }
    }

    proptest! {
        #[test]
        fn fuzz_reaper_control_frames_never_panic(
            cmd_bytes in proptest::collection::vec(any::<u8>(), REAPER_COMMAND_BYTES),
            reply_bytes in proptest::collection::vec(any::<u8>(), REAPER_REPLY_BYTES),
        ) {
            let mut c = [0u8; REAPER_COMMAND_BYTES];
            c.copy_from_slice(&cmd_bytes);
            let _ = ReaperCommand::decode(&c);

            let mut r = [0u8; REAPER_REPLY_BYTES];
            r.copy_from_slice(&reply_bytes);
            let _ = ReaperReply::decode(&r);
        }
    }
}
