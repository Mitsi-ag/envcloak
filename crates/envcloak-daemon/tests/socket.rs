//! Gate 20, socket hygiene (SPEC §4.2): the runtime directory is 0700 and
//! the socket 0600; a symlinked, foreign-owned, or group- or
//! world-writable directory is refused; a second instance is refused; a
//! stale socket is replaced only under the lock; another uid is rejected at
//! accept; a connection another process uses after the accept is closed.
//!
//! The other-uid checks need a second user and `sudo`: CI creates one on
//! Linux and names it in `ENVCLOAK_TEST_OTHER_USER`. Elsewhere they say
//! they did not run.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use common::{client, exe, run_paths, start};
use envcloak_ipc::view::VaultState;
use envcloak_testkit::{Daemon, TEST_PATH, TestHome, daemon_run_dir};

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().mode() & 0o7777
}

/// Starts a daemon that must refuse, and returns its exit code and log.
fn refused(home: &TestHome) -> (Option<i32>, String) {
    let mut d = Daemon::spawn(home, exe(), &[]);
    let status = d
        .wait_exit(Duration::from_secs(20))
        .expect("the daemon should have refused to start");
    (status.code(), d.log())
}

fn make_run_dir(home: &TestHome, m: u32) -> std::path::PathBuf {
    let dir = daemon_run_dir(home);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(m)).unwrap();
    dir
}

#[test]
fn the_directory_is_0700_and_the_socket_0600() {
    let home = TestHome::new();
    let _d = start(&home);
    let p = run_paths(&home);
    assert_eq!(mode(&p.dir), 0o700);
    assert_eq!(mode(&p.socket), 0o600);
    assert_eq!(mode(&p.lock), 0o600);
    let m = std::fs::symlink_metadata(&p.socket).unwrap();
    assert_eq!(m.uid(), envcloak_sys::effective_uid());
    assert!(std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()));
}

#[test]
fn a_directory_others_can_read_is_tightened() {
    let home = TestHome::new();
    let dir = make_run_dir(&home, 0o755);
    let _d = start(&home);
    assert_eq!(mode(&dir), 0o700);
}

#[test]
fn unsafe_directories_are_refused() {
    for m in [0o770, 0o720, 0o707, 0o777] {
        let home = TestHome::new();
        let dir = make_run_dir(&home, m);
        let (code, log) = refused(&home);
        assert_eq!(code, Some(1), "{m:o}: {log}");
        assert!(log.contains("envcloakd: runtime_dir:"), "{m:o}: {log}");
        assert!(log.contains("writable by other users"), "{m:o}: {log}");
        assert_eq!(mode(&dir), m, "a refused directory is left alone");
        assert!(!dir.join("envcloakd.sock").exists());
    }

    let home = TestHome::new();
    let dir = daemon_run_dir(&home);
    let elsewhere = home.root().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
    let (code, log) = refused(&home);
    assert_eq!(code, Some(1), "{log}");
    assert!(log.contains("symbolic link"), "{log}");
    assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());

    // A parent directory others can write to, without the sticky bit.
    let home = TestHome::new();
    let dir = make_run_dir(&home, 0o700);
    let parent = dir.parent().unwrap();
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let (code, log) = refused(&home);
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(code, Some(1), "{log}");
    assert!(log.contains("envcloakd: runtime_dir:"), "{log}");
}

#[test]
fn a_second_instance_is_refused() {
    let home = TestHome::new();
    let first = start(&home);
    let (code, log) = refused(&home);
    assert_eq!(code, Some(1), "{log}");
    assert!(log.contains("envcloakd: already_running:"), "{log}");
    // The first still serves on its socket.
    let st = client(&home).status().unwrap();
    assert_eq!(i64::from(st.daemon.pid), i64::from(first.pid()));
}

/// A socket left by a daemon that died is removed and replaced, but only
/// by the daemon that holds the lock; anything else in its place is
/// refused.
#[test]
fn a_stale_socket_is_replaced_and_anything_else_refused() {
    let home = TestHome::new();
    let p = run_paths(&home);
    make_run_dir(&home, 0o700);
    drop(UnixListener::bind(&p.socket).unwrap());
    let d = start(&home);
    assert_eq!(
        client(&home).status().unwrap().vault.state,
        VaultState::Absent
    );
    drop(d);

    // A killed daemon leaves its socket behind; the next one replaces it.
    assert!(p.socket.exists());
    let _d = start(&home);
    client(&home).status().unwrap();
    drop(_d);

    std::fs::remove_file(&p.socket).unwrap();
    std::fs::write(&p.socket, b"not a socket").unwrap();
    let (code, log) = refused(&home);
    assert_eq!(code, Some(1), "{log}");
    assert!(log.contains("envcloakd: socket_taken:"), "{log}");
    assert_eq!(std::fs::read(&p.socket).unwrap(), b"not a socket");
}

#[test]
fn a_socket_path_too_long_for_sun_path_is_refused() {
    let home = TestHome::new();
    let long = home.root().join("h".repeat(100));
    std::fs::create_dir(&long).unwrap();
    let mut cmd = Command::new(exe());
    home.apply(&mut cmd)
        .env("HOME", &long)
        .env("XDG_RUNTIME_DIR", &long);
    let mut d = Daemon::spawn_command(cmd, &[]);
    let status = d.wait_exit(Duration::from_secs(20)).unwrap();
    assert_eq!(status.code(), Some(1));
    let log = d.log();
    assert!(log.contains("too long for a Unix socket"), "{log}");
}

/// Linux without `XDG_RUNTIME_DIR`: the socket goes under
/// `XDG_STATE_HOME`, with a warning.
#[cfg(target_os = "linux")]
#[test]
fn linux_without_a_runtime_dir_the_daemon_falls_back_and_warns() {
    let home = TestHome::new();
    let mut cmd = Command::new(exe());
    home.apply(&mut cmd).env_remove("XDG_RUNTIME_DIR");
    let d = Daemon::start_command(cmd, &[]);
    let log = d.log();
    assert!(log.contains("warning: XDG_RUNTIME_DIR is not set"), "{log}");
    let dir = home.root().join("state/envcloak/run");
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("envcloakd.sock")), 0o600);
    let st = envcloak_ipc::Client::connect(&envcloak_ipc::RunPaths::under(&dir).unwrap())
        .unwrap()
        .status()
        .unwrap();
    assert!(st.daemon.runtime_dir_fallback);
}

/// A `python3` connector that sends `status` on the daemon's socket
/// `argv[1]`, then forks a holder of the connection that sends `status`
/// on it, then sends another itself. Each line it prints is `<who> <pid>
/// answered <id>`, or `closed` for a request the daemon did not answer.
const PASSED_ON: &str = r#"import json, os, socket, struct, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(30)
s.connect(sys.argv[1])
def ask(i):
    try:
        b = json.dumps({'jsonrpc': '2.0', 'id': i, 'method': 'status'}).encode()
        s.sendall(struct.pack('>I', len(b)) + b)
        h = s.recv(4, socket.MSG_WAITALL)
        if len(h) < 4:
            return 'closed'
        n = struct.unpack('>I', h)[0]
        return 'answered %d' % json.loads(s.recv(n, socket.MSG_WAITALL))['id']
    except OSError:
        return 'closed'
print('connector', os.getpid(), ask(1), flush=True)
pid = os.fork()
if pid == 0:
    try:
        print('holder', os.getpid(), ask(2), flush=True)
    finally:
        os._exit(0)
os.waitpid(pid, 0)
print('connector', os.getpid(), ask(3), flush=True)
"#;

/// Review T7 open 1: a connection is served only for the process
/// identified at accept. The daemon reads the peer again before each
/// request: on macOS the kernel names the last process to use the
/// client's socket, so a process the connection was passed to (here
/// across `fork`) that sends a request is not answered as the connector
/// (its evidence, its proofs, its place in the per-process count and the
/// pid in the audit log), and the connection is closed. Linux keeps the
/// connecting process for the socket's life: the holder acts as the
/// connector there, as the connector could itself.
#[test]
fn a_connection_used_by_another_process_is_closed() {
    let home = TestHome::new();
    let d = start(&home);
    let out = Command::new("python3")
        .args(["-c", PASSED_ON])
        .arg(run_paths(&home).socket)
        .env_clear()
        .env("PATH", TEST_PATH)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let lines: Vec<Vec<&str>> = text
        .lines()
        .map(|l| l.split(' ').collect::<Vec<_>>())
        .collect();
    assert_eq!(lines.len(), 3, "{text}");
    let connector = lines[0][1];
    assert_eq!(
        lines[0],
        ["connector", connector, "answered", "1"],
        "{text}"
    );
    assert_eq!(lines[1][0], "holder", "{text}");
    assert_ne!(lines[1][1], connector, "{text}");
    let log = d.log();
    let closed =
        format!("envcloakd: closed a connection now used by another process than pid {connector},");
    if cfg!(target_os = "macos") {
        assert_eq!(lines[1][2..], ["closed"], "{text}");
        assert_eq!(lines[2], ["connector", connector, "closed"], "{text}");
        assert!(log.contains(&closed), "{log}");
    } else {
        assert_eq!(lines[1][2..], ["answered", "2"], "{text}");
        assert_eq!(
            lines[2],
            ["connector", connector, "answered", "3"],
            "{text}"
        );
        assert!(!log.contains(&closed), "{log}");
    }
    // The daemon serves new connections as before.
    assert_eq!(
        client(&home).status().unwrap().vault.state,
        VaultState::Absent
    );
}

// ------------------------------------------------ another uid (Linux CI)

/// The second user, when this environment has one and `sudo` can act as
/// it. CI on Linux must have it.
fn other_user() -> Option<String> {
    let user = std::env::var("ENVCLOAK_TEST_OTHER_USER").ok();
    if user.is_none() && cfg!(target_os = "linux") && std::env::var_os("GITHUB_ACTIONS").is_some() {
        panic!("CI must name a second user in ENVCLOAK_TEST_OTHER_USER");
    }
    if user.is_none() {
        eprintln!("skipped: set ENVCLOAK_TEST_OTHER_USER to a user sudo can act as");
    }
    user
}

fn sudo(args: &[&str]) -> std::process::Output {
    let out = Command::new("sudo").arg("-n").args(args).output().unwrap();
    assert!(out.status.success(), "sudo {args:?}: {out:?}");
    out
}

fn uid_of(user: &str) -> u32 {
    let out = Command::new("id").args(["-u", user]).output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

#[test]
fn a_foreign_owned_directory_is_refused() {
    let Some(user) = other_user() else { return };
    let home = TestHome::new();
    let dir = make_run_dir(&home, 0o700);
    sudo(&["chown", &user, dir.to_str().unwrap()]);
    let (code, log) = refused(&home);
    sudo(&[
        "chown",
        &envcloak_sys::effective_uid().to_string(),
        dir.to_str().unwrap(),
    ]);
    assert_eq!(code, Some(1), "{log}");
    assert!(log.contains("belongs to another user"), "{log}");
}

/// A connection from another uid reaches the socket only if the
/// directory and socket permissions are loosened by hand; the daemon then
/// closes it at accept, answers nothing, and audits it.
#[test]
fn another_uid_is_rejected_at_accept() {
    let Some(user) = other_user() else { return };
    let home = TestHome::new();
    let d = start(&home);
    let p = run_paths(&home);
    // Let the other user reach the socket: every directory down to it
    // searchable, and the socket writable by anyone.
    let mut dir = p.dir.clone();
    loop {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o711)).unwrap();
        if dir == home.root() {
            break;
        }
        dir = dir.parent().unwrap().to_path_buf();
    }
    std::fs::set_permissions(&p.socket, std::fs::Permissions::from_mode(0o666)).unwrap();

    let script = "import socket, struct, sys\n\
s = socket.socket(socket.AF_UNIX)\n\
s.connect(sys.argv[1])\n\
body = b'{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"status\"}'\n\
try:\n    s.sendall(struct.pack('>I', len(body)) + body)\nexcept OSError:\n    pass\n\
s.settimeout(10)\n\
data = b''\n\
try:\n    while True:\n        b = s.recv(4096)\n        if not b:\n            break\n        data += b\nexcept OSError:\n    pass\n\
print('received', len(data))\n";
    let out = sudo(&[
        "-u",
        &user,
        "python3",
        "-c",
        script,
        p.socket.to_str().unwrap(),
    ]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.trim(), "received 0", "{text}");
    let log = d.log();
    let line = format!(
        "audit: rejected connection reason=foreign_uid uid={}",
        uid_of(&user)
    );
    assert!(log.contains(&line), "{log}");
    // This user is still served.
    client(&home).status().unwrap();
}
