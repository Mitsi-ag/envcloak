//! The verified client (SPEC §4.2, gate 21): it never sends to a socket it
//! could not verify, it tells "no daemon" from "not trusted", and its
//! socket is close-on-exec. The servers here are threads of this test,
//! running as this uid; a foreign server is simulated with
//! `Client::connect_expecting_uid` (the real other-uid case runs in the
//! daemon's tests on Linux CI).
#![allow(clippy::unwrap_used)]

use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::mpsc;
use std::thread::JoinHandle;

use envcloak_core::SecretBytes;
use envcloak_ipc::proto::{self, IncomingRequest, UnlockParams};
use envcloak_ipc::view::LockedView;
use envcloak_ipc::{
    Client, ClientError, DaemonIdentity, ErrorKind, Frame, FrameError, MAX_FRAME, RunPathErrorKind,
    RunPaths, Unverified,
};
use envcloak_testkit::{TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels};

fn run_paths(home: &TestHome) -> RunPaths {
    RunPaths::under(home.root().join("run").join("envcloak")).unwrap()
}

fn make_dir(p: &RunPaths) {
    std::fs::create_dir(&p.dir).unwrap();
    std::fs::set_permissions(&p.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// A server thread that records every byte it receives until the client
/// hangs up, and answers each request frame with `answer`.
fn server(
    p: &RunPaths,
    answer: impl Fn(&Frame) -> Vec<u8> + Send + 'static,
) -> JoinHandle<Vec<u8>> {
    let l = UnixListener::bind(&p.socket).unwrap();
    let (tx, rx) = mpsc::channel();
    let h = std::thread::spawn(move || {
        tx.send(()).unwrap();
        let (mut s, _) = l.accept().unwrap();
        let mut seen = Vec::new();
        loop {
            let mut header = [0u8; 4];
            if s.read_exact(&mut header).is_err() {
                break;
            }
            seen.extend_from_slice(&header);
            let len = u32::from_be_bytes(header) as usize;
            let mut body = vec![0u8; len];
            s.read_exact(&mut body).unwrap();
            seen.extend_from_slice(&body);
            let mut wire = header.to_vec();
            wire.extend_from_slice(&body);
            let f = Frame::read_from(&mut &wire[..]).unwrap();
            let out = answer(&f);
            std::io::Write::write_all(&mut s, &out).unwrap();
        }
        seen
    });
    rx.recv().unwrap();
    h
}

fn wire(f: &Frame) -> Vec<u8> {
    let mut v = Vec::new();
    f.write_to(&mut v).unwrap();
    v
}

fn answer_locked(f: &Frame) -> Vec<u8> {
    let req = IncomingRequest::parse(f).unwrap();
    wire(
        &proto::result_frame(
            req.id,
            &LockedView {
                was_unlocked: false,
            },
        )
        .unwrap(),
    )
}

#[test]
fn no_directory_socket_or_listener_means_no_daemon() {
    let home = TestHome::new();
    let p = run_paths(&home);
    assert_eq!(Client::connect(&p).unwrap_err(), ClientError::Unavailable);
    make_dir(&p);
    assert_eq!(Client::connect(&p).unwrap_err(), ClientError::Unavailable);
    // A socket left by a daemon that is gone.
    drop(UnixListener::bind(&p.socket).unwrap());
    assert!(p.socket.exists());
    assert_eq!(Client::connect(&p).unwrap_err(), ClientError::Unavailable);
    assert_eq!(ClientError::Unavailable.token(), "daemon_unavailable");
}

#[test]
fn an_unsafe_directory_or_socket_is_not_trusted() {
    let home = TestHome::new();
    let p = run_paths(&home);
    let elsewhere = home.root().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &p.dir).unwrap();
    let e = Client::connect(&p).unwrap_err();
    assert_eq!(
        e,
        ClientError::Unverified(Unverified::Directory(RunPathErrorKind::Symlink))
    );
    assert_eq!(e.token(), "daemon_unverified");
    std::fs::remove_file(&p.dir).unwrap();

    make_dir(&p);
    for mode in [0o770, 0o702, 0o777] {
        std::fs::set_permissions(&p.dir, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            Client::connect(&p).unwrap_err(),
            ClientError::Unverified(Unverified::Directory(RunPathErrorKind::OpenPermissions)),
            "{mode:o}"
        );
    }
    std::fs::set_permissions(&p.dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    // A parent others can write to (and not sticky).
    let parent = p.dir.parent().unwrap();
    let before = std::fs::metadata(parent).unwrap().permissions();
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let e = Client::connect(&p).unwrap_err();
    std::fs::set_permissions(parent, before).unwrap();
    assert_eq!(
        e,
        ClientError::Unverified(Unverified::Directory(RunPathErrorKind::OpenParent))
    );

    // A regular file or a symlink where the socket belongs.
    std::fs::write(&p.socket, b"").unwrap();
    assert_eq!(
        Client::connect(&p).unwrap_err(),
        ClientError::Unverified(Unverified::Socket(RunPathErrorKind::NotSocket))
    );
    std::fs::remove_file(&p.socket).unwrap();
    let real = home.root().join("tmp").join("s");
    drop(UnixListener::bind(&real).unwrap());
    std::os::unix::fs::symlink(&real, &p.socket).unwrap();
    assert_eq!(
        Client::connect(&p).unwrap_err(),
        ClientError::Unverified(Unverified::Socket(RunPathErrorKind::Symlink))
    );
}

#[test]
fn a_verified_daemon_is_called_over_a_cloexec_socket() {
    let home = TestHome::new();
    let p = run_paths(&home);
    make_dir(&p);
    let h = server(&p, answer_locked);
    let mut c = Client::connect(&p).unwrap();
    assert!(envcloak_sys::cloexec_flag(c.as_fd()).unwrap());
    assert_eq!(c.identity(), DaemonIdentity::Unverified);
    assert!(!c.lock().unwrap().was_unlocked);
    assert!(!c.lock().unwrap().was_unlocked);
    drop(c);
    assert!(!h.join().unwrap().is_empty());
}

/// Gate 21: values and proofs are never sent to an unverified peer. The
/// server runs as this uid; the client is told to expect another, as if a
/// program running as another user had bound the socket.
#[test]
fn a_server_of_another_uid_gets_nothing() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let p = run_paths(&home);
    make_dir(&p);
    let h = server(&p, answer_locked);
    let other = envcloak_sys::effective_uid().wrapping_add(1);
    let e = Client::connect_expecting_uid(&p, other).unwrap_err();
    assert_eq!(e, ClientError::Unverified(Unverified::ForeignServer));
    assert_eq!(e.token(), "daemon_unverified");
    assert_no_canary(format!("{e} {e:?}").as_bytes(), &cs);
    // The server saw the connection and not one byte.
    assert!(h.join().unwrap().is_empty());

    // Control: the same kind of server, expected as this uid, gets the
    // request.
    let pass = by_label(&cs, labels::VAULT_PASSPHRASE).value();
    std::fs::remove_file(&p.socket).unwrap();
    let h = server(&p, |f| {
        let req = IncomingRequest::parse(f).unwrap();
        let _: UnlockParams = req.params().unwrap();
        wire(&proto::error_frame(Some(req.id), &ErrorKind::WrongPassphrase.into()).unwrap())
    });
    let mut c = Client::connect(&p).unwrap();
    let e = c.unlock(SecretBytes::copy_from(pass)).unwrap_err();
    assert_eq!(e.token(), "wrong_passphrase");
    drop(c);
    assert!(!h.join().unwrap().is_empty());
}

#[test]
fn oversized_or_mismatched_responses_are_refused() {
    let home = TestHome::new();
    let p = run_paths(&home);
    make_dir(&p);
    let h = server(&p, |_| {
        let mut v = u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes().to_vec();
        v.extend_from_slice(b"{}");
        v
    });
    let mut c = Client::connect(&p).unwrap();
    assert_eq!(
        c.lock().unwrap_err(),
        ClientError::Frame(FrameError::TooLarge)
    );
    drop(c);
    h.join().unwrap();

    std::fs::remove_file(&p.socket).unwrap();
    let h = server(&p, |f| {
        let req = IncomingRequest::parse(f).unwrap();
        wire(
            &proto::result_frame(
                req.id + 1,
                &LockedView {
                    was_unlocked: false,
                },
            )
            .unwrap(),
        )
    });
    let mut c = Client::connect(&p).unwrap();
    assert_eq!(c.lock().unwrap_err(), ClientError::Protocol);
    drop(c);
    h.join().unwrap();
}

#[test]
fn the_socket_path_must_fit() {
    let long = Path::new("/tmp").join("d".repeat(120));
    assert_eq!(
        RunPaths::under(long).unwrap_err().kind(),
        RunPathErrorKind::SocketPathTooLong
    );
}

/// The client checks the daemon's uid but, in M1, not its code identity,
/// so a program running as the user can answer `status` in its place. The
/// text fields it could fill are replaced with fixed text unless they have
/// the shape a real daemon sends: a version of 1 to 32 characters from
/// `[0-9A-Za-z.+-]`, and a reason from `proto::REASONS`. Nothing it sends
/// can then put a terminal control sequence on the user's screen.
#[test]
fn status_text_from_the_daemon_is_checked_before_use() {
    let status = |version: &str, unavailable: &str| {
        serde_json::json!({
            "daemon": {
                "version": version,
                "pid": 1,
                "hardening": {"core_dumps_off": true, "non_dumpable": true, "hardened_runtime": null},
                "runtime_dir_fallback": false
            },
            "vault": {
                "state": "unavailable", "integrity": null, "read_only": false,
                "unavailable": unavailable, "busy": false, "failed_unlocks": 0
            },
            "lock": {"last_reason": null, "idle_limit_secs": 28800, "idle_remaining_secs": null}
        })
    };
    let cases = [
        ("0.1.0", "damaged", "0.1.0", "damaged"),
        (
            "1.2.3-rc.1+build.7",
            "disk_full",
            "1.2.3-rc.1+build.7",
            "disk_full",
        ),
        (
            "\u{1b}[2J\u{1b}]0;owned\u{7}",
            "\u{1b}[31mdamaged",
            "unrecognized",
            "unknown",
        ),
        ("0.1.0\n", "damaged\r", "unrecognized", "unknown"),
        ("", "", "unrecognized", "unknown"),
        (&"9".repeat(33), "not_a_reason", "unrecognized", "unknown"),
    ];
    for (version, unavailable, want_version, want_reason) in cases {
        let home = TestHome::new();
        let p = run_paths(&home);
        make_dir(&p);
        let body = status(version, unavailable);
        let srv = server(&p, move |f| {
            let req = IncomingRequest::parse(f).unwrap();
            wire(&proto::result_frame(req.id, &body).unwrap())
        });
        let got = Client::connect(&p).unwrap().status().unwrap();
        assert_eq!(got.daemon.version, want_version, "{version:?}");
        assert_eq!(
            got.vault.unavailable.as_deref(),
            Some(want_reason),
            "{unavailable:?}"
        );
        srv.join().unwrap();
    }
}
