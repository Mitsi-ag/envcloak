//! The processes a managed server's values go to, which the daemon starts
//! itself (SPEC §6.6; M2 plan D-36; task M2-27): EnvCloak's runner,
//! `envcloak run --launch <id>`, for a stdio server, and its relay,
//! `envcloak mcp-bridge --relay`, for a bridged HTTP server. No value goes
//! back to the client that asked: it gets `started`, and the values go on
//! a control channel only these children hold.
//!
//! **The anchor** ([`Anchor`]): the `envcloak` beside `envcloakd`, taken
//! once, when the daemon starts. On Linux the daemon copies it into a
//! sealed memory file ([`envcloak_sys::launch::SealedImage`]), hashes the
//! sealed bytes, and starts every runner from that same copy
//! (`execveat`): an `envcloak` rewritten or replaced since leaves the
//! daemon starting the image it took, until it restarts. On macOS it
//! records the file's code directory hash and starts each runner suspended,
//! resuming it only when the kernel's cdhash of the started process is the
//! anchor's (and, for a Developer ID build, its Team ID is `envcloakd`'s
//! own); otherwise it kills it through its handle before it runs. An
//! anchor that could not be taken, or a runner that could not be started
//! from it, is `runner_unavailable`: nothing falls back to the file.
//!
//! **What a runner gets**: the client's pipe ends as its standard input,
//! output and error (`/dev/null` for standard error when none was handed
//! over), the control channel at
//! [`envcloak_ipc::control::CONTROL_FD`], the lifeline at
//! [`envcloak_ipc::control::LIFELINE_FD`], and for a launch the program to
//! run ([`envcloak_ipc::control::IMAGE_FD`], Linux) and the checked working
//! directory ([`envcloak_ipc::control::CWD_FD`]); every other descriptor is
//! closed. Its environment is a fixed list read from the daemon's own
//! (`HOME`, `USER`, `LOGNAME`, `LANG`, `LC_*`, `TZ`, `TMPDIR` and the
//! `XDG_*` directories, so it finds the daemon's socket) and a fixed
//! `PATH`; a test build adds its test hooks' variables. It leads a session
//! of its own and is never given `PR_SET_PDEATHSIG`: it outlives a daemon
//! restart (the systemd unit has `KillMode=process`; launchd's job cleanup
//! does not reach a process that leads its own session, measured on macOS
//! 26.4), and the new daemon holds no handle to it.

use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
use envcloak_ipc::control::IMAGE_FD;
use envcloak_ipc::control::{self, CONTROL_FD, CWD_FD, FromRunner, LIFELINE_FD, ToRunner};
use envcloak_ipc::proto::{ErrorKind, FdRole};
use envcloak_ipc::{Frame, RpcError};
use envcloak_sys::OwnedChild;
use envcloak_sys::fdpass::{Access, DescriptorKind, descriptor_kind};
use envcloak_sys::launch::{Program, Session, Spawn, spawn};

use crate::launch_check::{CheckedExec, CheckedLaunch};

/// The most descriptors one request may hand over.
pub(crate) const MAX_REQUEST_FDS: usize = 4;

/// How long the daemon waits for a runner's `ConfirmSpawn` (macOS).
const CONFIRM_WAIT: Duration = Duration::from_secs(10);

/// The `PATH` a runner gets. It never looks a program up: the server's
/// `PATH` is the record's.
const RUNNER_PATH: &[u8] = b"/usr/bin:/bin";

/// Why there is no anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnchorError {
    /// No `envcloak` beside `envcloakd`, or not a regular file.
    NotFound,
    /// Linux: the sealed copy could not be made (an executable memory file
    /// refused by the system's policy) or checked.
    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    Copy,
    /// macOS: the file has no code directory the kernel would check.
    #[cfg_attr(any(target_os = "linux", target_os = "android"), allow(dead_code))]
    Unsigned,
}

impl AnchorError {
    fn word(self) -> &'static str {
        match self {
            AnchorError::NotFound => "not_found",
            AnchorError::Copy => "copy_refused",
            AnchorError::Unsigned => "unsigned",
        }
    }
}

/// The image a runner is started from (see the module documentation).
#[derive(Debug)]
pub(crate) struct Anchor(Result<Image, AnchorError>);

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
struct Image {
    sealed: envcloak_sys::launch::SealedImage,
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[derive(Debug)]
struct Image {
    path: PathBuf,
    cdhash: Vec<u8>,
    /// `envcloakd`'s own Team ID, for a Developer ID build.
    team: Option<String>,
}

impl Anchor {
    /// The anchor, taken now (at daemon start). A failure is kept and
    /// logged: managed requests are then answered `runner_unavailable`.
    pub(crate) fn at_start() -> Anchor {
        let a = Anchor(take());
        match &a.0 {
            Ok(_) => {}
            Err(e) => log_line!(
                "envcloakd: warning: managed servers cannot be started ({}): the envcloak beside \
                 envcloakd could not be taken as the runner's image",
                e.word()
            ),
        }
        a
    }

    /// An anchor that is not there, for tests.
    #[cfg(test)]
    pub(crate) fn unavailable() -> Anchor {
        Anchor(Err(AnchorError::NotFound))
    }
}

/// The `envcloak` beside this daemon, canonical.
fn beside() -> Result<PathBuf, AnchorError> {
    let me = std::env::current_exe().map_err(|_| AnchorError::NotFound)?;
    let dir = me.parent().ok_or(AnchorError::NotFound)?;
    std::fs::canonicalize(dir.join("envcloak")).map_err(|_| AnchorError::NotFound)
}

fn open_regular(path: &std::path::Path) -> Result<File, AnchorError> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| AnchorError::NotFound)?;
    if !f.metadata().is_ok_and(|m| m.is_file()) {
        return Err(AnchorError::NotFound);
    }
    Ok(f)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn take() -> Result<Image, AnchorError> {
    let file = open_regular(&beside()?)?;
    envcloak_sys::fail_point("launch.anchor").map_err(|_| AnchorError::Copy)?;
    let sealed = envcloak_sys::launch::SealedImage::copy_from(
        file.as_fd(),
        envcloak_sys::codesign::MAX_EXECUTABLE,
    )
    .map_err(|_| AnchorError::Copy)?;
    // The sealed bytes, hashed once sealed: what every runner runs.
    let digest = crate::launch_check::sha256_of_image(&sealed).map_err(|_| AnchorError::Copy)?;
    if envcloak_sys::test_trace() {
        log_line!(
            "envcloakd: test: anchor sha256 {}",
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
    Ok(Image { sealed })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn take() -> Result<Image, AnchorError> {
    let path = beside()?;
    let file = open_regular(&path)?;
    let cd = envcloak_sys::codesign::code_directory(&file)
        .map_err(|_| AnchorError::Unsigned)?
        .ok_or(AnchorError::Unsigned)?;
    let cdhash = crate::launch_check::cdhash_of(&cd).ok_or(AnchorError::Unsigned)?;
    let me = i32::try_from(std::process::id()).map_err(|_| AnchorError::NotFound)?;
    let team = envcloak_sys::proc_info(me)
        .ok()
        .and_then(|p| p.exe)
        .and_then(|e| e.signature)
        .and_then(|s| s.team_id);
    Ok(Image { path, cdhash, team })
}

/// The pipe ends a managed request handed over, checked: each role once,
/// in the order the request names them ([`FdRole::well_formed`]), standard
/// input and the lifeline readable, standard output and error writable,
/// each a pipe or a socket.
#[derive(Debug)]
pub(crate) struct ClientEnds {
    stdin: OwnedFd,
    stdout: OwnedFd,
    stderr: Option<OwnedFd>,
    lifeline: OwnedFd,
}

impl ClientEnds {
    /// The ends `fds`, whose roles `roles` names, for a launch (`launch`)
    /// or a bridge.
    ///
    /// # Errors
    /// `invalid_params` (`invalid_descriptors`) for anything else; the
    /// descriptors are closed.
    pub(crate) fn from_request(
        fds: Vec<OwnedFd>,
        roles: &[FdRole],
        launch: bool,
    ) -> Result<ClientEnds, RpcError> {
        let bad = || RpcError::new(ErrorKind::InvalidParams);
        if fds.len() != roles.len() || !FdRole::well_formed(roles, launch) {
            return Err(bad());
        }
        let readable = |a: Access| matches!(a, Access::Read | Access::ReadWrite);
        let writable = |a: Access| matches!(a, Access::Write | Access::ReadWrite);
        let mut stdin = None;
        let mut stdout = None;
        let mut stderr = None;
        let mut lifeline = None;
        for (fd, role) in fds.into_iter().zip(roles) {
            let (kind, access) = descriptor_kind(fd.as_fd()).map_err(|_| bad())?;
            if kind == DescriptorKind::Other {
                return Err(bad());
            }
            let fits = match role {
                FdRole::Stdin | FdRole::Lifeline => readable(access),
                FdRole::Stdout | FdRole::Stderr => writable(access),
            };
            if !fits {
                return Err(bad());
            }
            match role {
                FdRole::Stdin => stdin = Some(fd),
                FdRole::Stdout => stdout = Some(fd),
                FdRole::Stderr => stderr = Some(fd),
                FdRole::Lifeline => lifeline = Some(fd),
            }
        }
        Ok(ClientEnds {
            stdin: stdin.ok_or_else(bad)?,
            stdout: stdout.ok_or_else(bad)?,
            stderr,
            lifeline: lifeline.ok_or_else(bad)?,
        })
    }
}

/// What the daemon starts.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Role<'a> {
    /// `envcloak run --launch <id>`, with the checked launch.
    Runner {
        launch: &'a str,
        checked: &'a CheckedLaunch,
    },
    /// `envcloak mcp-bridge --relay`.
    Relay,
}

/// The runner's environment, each `NAME=value`: see the module
/// documentation.
fn runner_env() -> Vec<Vec<u8>> {
    let keep = |name: &[u8]| {
        matches!(
            name,
            b"HOME" | b"USER" | b"LOGNAME" | b"LANG" | b"TZ" | b"TMPDIR"
        ) || name.starts_with(b"LC_")
            || name.starts_with(b"XDG_")
    };
    let pair = |k: &[u8], v: &[u8]| [k, b"=", v].concat();
    let mut env: Vec<Vec<u8>> = std::env::vars_os()
        .filter(|(k, _)| keep(k.as_bytes()))
        .map(|(k, v)| pair(k.as_bytes(), v.as_bytes()))
        .collect();
    env.push(pair(b"PATH", RUNNER_PATH));
    env.extend(
        envcloak_sys::test_hook_vars()
            .into_iter()
            .map(|(k, v)| pair(k.as_bytes(), v.as_bytes())),
    );
    env
}

/// A runner or relay the daemon started, holding nothing yet: the values
/// go on its control channel ([`Started::release`]).
#[derive(Debug)]
pub(crate) struct Started {
    child: OwnedChild,
    control: UnixStream,
    /// macOS: the code directory hash the server the runner starts
    /// suspended must have, before it may run.
    confirm: Option<Vec<u8>>,
}

/// Starts the runner or relay `role` from `anchor` on `ends`.
///
/// # Errors
/// `runner_unavailable`: no anchor, or the start failed (or, on macOS, the
/// started process was not the anchor's image, and was killed before it
/// ran).
pub(crate) fn start(
    anchor: &Anchor,
    role: Role<'_>,
    ends: &ClientEnds,
) -> Result<Started, RpcError> {
    let unavailable = || RpcError::new(ErrorKind::RunnerUnavailable);
    let image = anchor.0.as_ref().map_err(|_| unavailable())?;
    envcloak_sys::fail_point("launch.runner").map_err(|_| unavailable())?;
    let (ours, theirs) = UnixStream::pair().map_err(|_| unavailable())?;
    let devnull;
    let stderr: BorrowedFd<'_> = match &ends.stderr {
        Some(e) => e.as_fd(),
        None => {
            devnull = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .map_err(|_| unavailable())?;
            devnull.as_fd()
        }
    };
    let mut fds: Vec<(BorrowedFd<'_>, i32)> = vec![
        (ends.stdin.as_fd(), 0),
        (ends.stdout.as_fd(), 1),
        (stderr, 2),
        (theirs.as_fd(), CONTROL_FD),
        (ends.lifeline.as_fd(), LIFELINE_FD),
    ];
    let mut confirm = None;
    let argv: Vec<&[u8]> = match role {
        Role::Runner { launch, checked } => {
            match &checked.exec {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                CheckedExec::Image(i) => fds.push((i.as_fd(), IMAGE_FD)),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                CheckedExec::Descriptor { file, .. } => fds.push((file.as_fd(), IMAGE_FD)),
                CheckedExec::Path { confirm: c, .. } => confirm.clone_from(c),
            }
            fds.push((checked.cwd.as_fd(), CWD_FD));
            vec![b"envcloak", b"run", b"--launch", launch.as_bytes()]
        }
        Role::Relay => vec![b"envcloak", b"mcp-bridge", b"--relay"],
    };
    let env = runner_env();
    let env: Vec<&[u8]> = env.iter().map(Vec::as_slice).collect();
    let child = spawn_anchor(image, &argv, &env, &fds).map_err(|()| unavailable())?;
    drop(theirs);
    Ok(Started {
        child,
        control: ours,
        confirm,
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn spawn_anchor(
    image: &Image,
    argv: &[&[u8]],
    env: &[&[u8]],
    fds: &[(BorrowedFd<'_>, i32)],
) -> Result<OwnedChild, ()> {
    spawn(&Spawn {
        program: Program::Descriptor(image.sealed.as_fd()),
        argv,
        env,
        fds,
        cwd: None,
        session: Session::New,
        suspended: false,
    })
    .map_err(|_| ())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn spawn_anchor(
    image: &Image,
    argv: &[&[u8]],
    env: &[&[u8]],
    fds: &[(BorrowedFd<'_>, i32)],
) -> Result<OwnedChild, ()> {
    let child = spawn(&Spawn {
        program: Program::Path(image.path.as_os_str().as_bytes()),
        argv,
        env,
        fds,
        cwd: None,
        session: Session::New,
        suspended: true,
    })
    .map_err(|_| ())?;
    // The started process must be the anchor's image before any of it
    // runs: the kernel's cdhash, read while it is suspended. Every way out
    // but the resumed runner kills it through its handle first: nothing
    // stays suspended, or unreaped, behind a refusal.
    let Ok(pid) = i32::try_from(child.id()) else {
        let _ = child.kill_and_reap();
        return Err(());
    };
    let sig = envcloak_sys::proc_info(pid)
        .ok()
        .and_then(|p| p.exe)
        .and_then(|e| e.signature);
    let same = sig.as_ref().is_some_and(|s| {
        s.cdhash.is_some_and(|h| h[..] == image.cdhash[..])
            && (image.team.is_none() || s.team_id == image.team)
    });
    if !same {
        let _ = child.kill_and_reap();
        return Err(());
    }
    // A test makes the resumption fail here.
    let resumed = envcloak_sys::fail_point("launch.anchor_resume").and_then(|()| child.resume());
    if resumed.is_err() {
        let _ = child.kill_and_reap();
        return Err(());
    }
    Ok(child)
}

impl Started {
    /// Sends the values (`release`, a framed [`ToRunner::Release`]) and,
    /// on macOS, answers the runner's `ConfirmSpawn`: `Confirmed` only for
    /// a child of this runner whose kernel cdhash is the record's. Then
    /// hands the runner to a thread that reaps it when it exits.
    ///
    /// # Errors
    /// `runner_unavailable` when the values could not be sent;
    /// `managed_launch_changed` when the started server was not the
    /// registered image (the runner kills it before it runs).
    pub(crate) fn release(self, release: &Frame) -> Result<(), RpcError> {
        let Started {
            child,
            control,
            confirm,
        } = self;
        let mut w = &control;
        if release.write_to(&mut w).is_err() {
            let _ = child.kill_and_reap();
            return Err(RpcError::new(ErrorKind::RunnerUnavailable));
        }
        let outcome = match confirm {
            None => Ok(()),
            Some(expected) => confirm_spawn(&control, &child, &expected),
        };
        drop(control);
        match &outcome {
            // The runner never asked, or was never answered: it holds the
            // values, and its client was told the launch failed. It goes.
            Err(e) if e.kind == ErrorKind::RunnerUnavailable => {
                let _ = child.kill_and_reap();
            }
            // Confirmed, or refused (the runner kills its server and
            // exits on its own).
            _ => reap_later(child),
        }
        outcome
    }

    /// Kills the runner, which received nothing.
    pub(crate) fn abandon(self) {
        let _ = self.child.kill_and_reap();
    }
}

/// Waits for the runner's `ConfirmSpawn` and answers it (macOS).
fn confirm_spawn(
    control: &UnixStream,
    runner: &OwnedChild,
    expected: &[u8],
) -> Result<(), RpcError> {
    let changed = || RpcError::new(ErrorKind::ManagedLaunchChanged);
    let _ = control.set_read_timeout(Some(CONFIRM_WAIT));
    let Ok(FromRunner::ConfirmSpawn(pid)) = control::receive::<FromRunner>(control) else {
        return Err(RpcError::new(ErrorKind::RunnerUnavailable));
    };
    // A test stops here, with the server started and not yet answered: it
    // must have run nothing.
    envcloak_sys::pause_point("launch.confirm");
    let ok = i32::try_from(pid)
        .ok()
        .and_then(|pid| envcloak_sys::proc_info(pid).ok())
        .is_some_and(|p| {
            u32::try_from(p.ppid).is_ok_and(|ppid| ppid == runner.id())
                && p.exe
                    .and_then(|e| e.signature)
                    .and_then(|s| s.cdhash)
                    .is_some_and(|h| h[..] == *expected)
        });
    let answer = if ok {
        ToRunner::Confirmed
    } else {
        ToRunner::Refused
    };
    if control::send(control, &answer).is_err() {
        return Err(RpcError::new(ErrorKind::RunnerUnavailable));
    }
    if ok { Ok(()) } else { Err(changed()) }
}

/// Reaps `child` on a thread of its own once it exits. The thread holds the
/// only handle; nothing signals the runner after this.
fn reap_later(child: OwnedChild) {
    let _ = std::thread::Builder::new()
        .name("runner".into())
        .spawn(move || {
            let _ = child.reap();
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pipe() -> (OwnedFd, OwnedFd) {
        envcloak_sys::pipe_cloexec().unwrap()
    }

    /// The descriptors a request hands over are checked for their roles:
    /// a write end where a read end belongs, a regular file, a missing
    /// lifeline, too many or too few, and standard error for a bridge are
    /// refused; the right ones are taken.
    #[test]
    fn handed_over_descriptors_are_checked() {
        let roles = [FdRole::Stdin, FdRole::Stdout, FdRole::Lifeline];
        let ok = || {
            let (sr, _sw) = pipe();
            let (_or, ow) = pipe();
            let (lr, _lw) = pipe();
            vec![sr, ow, lr]
        };
        assert!(ClientEnds::from_request(ok(), &roles, true).is_ok());
        assert!(ClientEnds::from_request(ok(), &roles, false).is_ok());
        // Standard input given as a write end.
        let (_sr, sw) = pipe();
        let (_or, ow) = pipe();
        let (lr, _lw) = pipe();
        assert!(ClientEnds::from_request(vec![sw, ow, lr], &roles, true).is_err());
        // A regular file.
        let f = OwnedFd::from(tempfile::tempfile().unwrap());
        let (_or, ow) = pipe();
        let (lr, _lw) = pipe();
        assert!(ClientEnds::from_request(vec![f, ow, lr], &roles, true).is_err());
        // Counts that do not match the roles.
        let mut v = ok();
        v.pop();
        assert!(ClientEnds::from_request(v, &roles, true).is_err());
        // Standard error for a bridge.
        let four = [
            FdRole::Stdin,
            FdRole::Stdout,
            FdRole::Stderr,
            FdRole::Lifeline,
        ];
        let mk = || {
            let (sr, _sw) = pipe();
            let (_or, ow) = pipe();
            let (_er, ew) = pipe();
            let (lr, _lw) = pipe();
            vec![sr, ow, ew, lr]
        };
        assert!(ClientEnds::from_request(mk(), &four, true).is_ok());
        assert!(ClientEnds::from_request(mk(), &four, false).is_err());
    }

    /// No anchor, no runner: `runner_unavailable`, and nothing is started.
    #[test]
    fn no_anchor_is_runner_unavailable() {
        let (sr, _sw) = pipe();
        let (_or, ow) = pipe();
        let (lr, _lw) = pipe();
        let ends = ClientEnds::from_request(
            vec![sr, ow, lr],
            &[FdRole::Stdin, FdRole::Stdout, FdRole::Lifeline],
            false,
        )
        .unwrap();
        let e = start(&Anchor::unavailable(), Role::Relay, &ends).unwrap_err();
        assert_eq!(e.kind, ErrorKind::RunnerUnavailable);
    }
}
