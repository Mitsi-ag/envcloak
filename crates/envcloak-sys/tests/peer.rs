//! Peer credentials (SPEC §4.2, §4.3): the daemon's view of a client at
//! accept, and the client's view of the server. The processes are real:
//! this test process, and `python3` children that connect and wait.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};

use envcloak_sys::{
    PeerSource, StartTime, effective_uid, peer_identity, peer_uid, process_start_time,
};

fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ecp")
        .tempdir_in("/tmp")
        .unwrap()
}

/// The fallback switch is process-wide, so these tests run one at a time.
fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn own_pid() -> i32 {
    i32::try_from(std::process::id()).unwrap()
}

/// A `python3` process that connects to `sock`, prints `ready` and waits
/// for its stdin to close. Killed and reaped on drop.
struct Connector(Child);

impl Connector {
    fn start(sock: &Path) -> Self {
        let mut child = Command::new("python3")
            .args([
                "-c",
                "import socket, sys\n\
                 s = socket.socket(socket.AF_UNIX)\n\
                 s.connect(sys.argv[1])\n\
                 print('ready', flush=True)\n\
                 sys.stdin.read()\n",
            ])
            .arg(sock)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "ready");
        Connector(child)
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.0.id()).unwrap()
    }
}

impl Drop for Connector {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn listener() -> (tempfile::TempDir, PathBuf, UnixListener) {
    let dir = short_dir();
    let path = dir.path().join("s.sock");
    let l = UnixListener::bind(&path).unwrap();
    (dir, path, l)
}

fn expected_source() -> PeerSource {
    if cfg!(target_os = "macos") {
        PeerSource::AuditToken
    } else {
        PeerSource::PidFd
    }
}

#[test]
fn a_peer_in_this_process_is_this_process() {
    let _serial = serial();
    let (_dir, path, l) = listener();
    let client = UnixStream::connect(&path).unwrap();
    let (server, _) = l.accept().unwrap();

    let id = peer_identity(server.as_fd()).unwrap();
    assert_eq!(id.uid, effective_uid());
    assert_eq!(id.pid, own_pid());
    assert_eq!(id.start_time, process_start_time(own_pid()).unwrap());
    if cfg!(target_os = "macos") {
        assert_eq!(id.source, PeerSource::AuditToken);
        assert!(id.pidversion.is_some());
    } else {
        // SO_PEERPIDFD needs Linux 6.5; CI runs a newer kernel, where the
        // pidfd path must be the one taken.
        if std::env::var_os("GITHUB_ACTIONS").is_some() {
            assert_eq!(id.source, expected_source());
        }
        assert!(id.pidversion.is_none());
    }

    // And the client sees the server's uid.
    assert_eq!(peer_uid(client.as_fd()).unwrap(), effective_uid());
    assert_eq!(peer_uid(server.as_fd()).unwrap(), effective_uid());
}

#[test]
fn a_peer_in_another_process_is_that_process() {
    let _serial = serial();
    let (_dir, path, l) = listener();
    let child = Connector::start(&path);
    let (server, _) = l.accept().unwrap();
    let id = peer_identity(server.as_fd()).unwrap();
    assert_eq!(id.pid, child.pid());
    assert_eq!(id.uid, effective_uid());
    let start = process_start_time(child.pid()).unwrap();
    assert_eq!(id.start_time, start);
    // The child started after this process.
    assert!(start >= process_start_time(own_pid()).unwrap());
}

/// The `SO_PEERCRED` fallback, forced on a kernel that has
/// `SO_PEERPIDFD`, identifies the same process.
#[cfg(target_os = "linux")]
#[test]
fn linux_the_peercred_fallback_agrees_with_the_pidfd_path() {
    let _serial = serial();
    use envcloak_sys::testing::force_peercred_fallback;

    let (_dir, path, l) = listener();
    let child = Connector::start(&path);
    let (server, _) = l.accept().unwrap();
    let with_pidfd = peer_identity(server.as_fd()).unwrap();
    force_peercred_fallback(true);
    let fallback = peer_identity(server.as_fd());
    force_peercred_fallback(false);
    let fallback = fallback.unwrap();
    assert_eq!(fallback.source, PeerSource::PeerCred);
    assert_eq!(fallback.pid, child.pid());
    assert_eq!(fallback.uid, with_pidfd.uid);
    assert_eq!(fallback.start_time, with_pidfd.start_time);
}

/// A client that connected and then exited (and was reaped) is refused:
/// its start time can no longer be tied to it.
#[test]
fn a_peer_that_exited_before_the_accept_is_refused() {
    let _serial = serial();
    let (_dir, path, l) = listener();
    let child = Connector::start(&path);
    let pid = child.pid();
    drop(child);
    assert!(process_start_time(pid).is_err());
    let (server, _) = l.accept().unwrap();
    let err = peer_identity(server.as_fd()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");

    #[cfg(target_os = "linux")]
    {
        let child = Connector::start(&path);
        drop(child);
        let (server, _) = l.accept().unwrap();
        envcloak_sys::testing::force_peercred_fallback(true);
        let err = peer_identity(server.as_fd());
        envcloak_sys::testing::force_peercred_fallback(false);
        assert_eq!(err.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }
}

/// Turns the reused-pid pretence off, even when the test fails.
#[cfg(target_os = "linux")]
struct PretendReused;

#[cfg(target_os = "linux")]
impl PretendReused {
    fn start(pid: i32, start: StartTime) -> Self {
        envcloak_sys::testing::pretend_pid_reused(Some((pid, start)));
        PretendReused
    }
}

#[cfg(target_os = "linux")]
impl Drop for PretendReused {
    fn drop(&mut self) {
        envcloak_sys::testing::pretend_pid_reused(None);
        envcloak_sys::testing::force_peercred_fallback(false);
    }
}

/// Linux 6.5+: a peer that connected, exited and was reaped before the
/// accept, whose pid another process then took, is refused by its pidfd.
/// The kernel's reuse is stood in for: `/proc/<pid>/stat` reads report the
/// pid as a live process that started before the accept, as a reused pid
/// would. The pidfd path must refuse the connection without trusting that
/// read; the `SO_PEERCRED` fallback, the control, cannot tell and takes the
/// impostor for the peer. On CI's kernel the pidfd path must be the one a
/// live peer gets, so an error there cannot fall back unseen.
#[cfg(target_os = "linux")]
#[test]
fn linux_a_reaped_peer_whose_pid_was_reused_is_refused_by_its_pidfd() {
    use envcloak_sys::testing::force_peercred_fallback;

    let _serial = serial();
    let (_dir, path, l) = listener();
    let live = Connector::start(&path);
    let (server, _) = l.accept().unwrap();
    let source = peer_identity(server.as_fd()).unwrap().source;
    drop((server, live));
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        assert_eq!(source, PeerSource::PidFd);
    }

    let child = Connector::start(&path);
    let pid = child.pid();
    drop(child);
    // A start time before the accept: this process's own.
    let older = process_start_time(own_pid()).unwrap();
    let pretence = PretendReused::start(pid, older);
    assert_eq!(process_start_time(pid).unwrap(), older);
    let (server, _) = l.accept().unwrap();
    let with_pidfd = peer_identity(server.as_fd());
    force_peercred_fallback(true);
    let fallback = peer_identity(server.as_fd());
    drop(pretence);

    let fallback = fallback.unwrap();
    assert_eq!(fallback.source, PeerSource::PeerCred);
    assert_eq!(fallback.pid, pid);
    if source == PeerSource::PidFd {
        let err = with_pidfd.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
    } else {
        eprintln!("this kernel has no SO_PEERPIDFD; only the fallback was checked");
    }
}

#[test]
fn start_times_are_stable_and_missing_processes_are_not_found() {
    let _serial = serial();
    let a = process_start_time(own_pid()).unwrap();
    let b = process_start_time(own_pid()).unwrap();
    assert_eq!(a, b);
    assert_eq!(StartTime::from_raw(a.raw()), a);
    // pid 1 (launchd or init) started first. macOS does not show a
    // process running as root to other users.
    match process_start_time(1) {
        Ok(init) => assert!(init <= a),
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}"),
    }
    let err = process_start_time(i32::MAX).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
}
