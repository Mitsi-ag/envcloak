//! Gate 21, squatting (SPEC §4.2), end to end: a server that another user
//! bound gets refused, and never receives a passphrase. The squatter is a
//! `python3` process running as a second user; its socket is moved into
//! this user's runtime directory and handed to this user, so the file
//! checks pass and only the peer's credentials give it away.
//!
//! Needs a second user and `sudo`: CI creates one on Linux and names it in
//! `ENVCLOAK_TEST_OTHER_USER`. Elsewhere the test says it did not run. The
//! same check without a second user, with a same-uid server presented as
//! foreign, is in envcloak-ipc's `tests/client.rs`.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use common::{outside_dir, run, secret_file, stderr};
use envcloak_testkit::{
    TestHome, assert_no_canary, by_label, canaries, daemon_run_dir, daemon_socket, fresh_seed,
    labels,
};

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

/// Listens on argv[1] and appends to argv[2] how many bytes each
/// connection sent before it closed.
const SQUATTER: &str = "import socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
s.listen(16)
print('ready', flush=True)
while True:
    c, _ = s.accept()
    c.settimeout(5)
    n = 0
    try:
        while True:
            b = c.recv(65536)
            if not b:
                break
            n += len(b)
    except OSError:
        pass
    with open(sys.argv[2], 'a') as f:
        f.write('%d\\n' % n)
    c.close()
";

#[test]
fn a_socket_bound_by_another_user_gets_no_passphrase() {
    let Some(user) = other_user() else { return };
    let cs = canaries(fresh_seed());
    let pass = by_label(&cs, labels::VAULT_PASSPHRASE).value();
    let home = TestHome::new();
    let files = outside_dir();
    let pass_file = secret_file(files.path(), "pass", pass);
    let kit_file = files.path().join("kit");

    // The squatter's own directory, then its socket.
    let dir = std::path::PathBuf::from(format!("/tmp/ecq{}", std::process::id()));
    let dir_s = dir.to_str().unwrap();
    sudo(&["-u", &user, "mkdir", "-m", "0755", dir_s]);
    let sock = dir.join("s.sock");
    let record = dir.join("record");
    let python = common::python3();
    let mut squatter = Command::new("sudo")
        .args(["-n", "-u", &user])
        .arg(&python)
        .args(["-c", SQUATTER])
        .arg(&sock)
        .arg(&record)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(squatter.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "ready");

    // Moved into this user's private runtime directory and given to this
    // user: the directory and the socket file pass every check.
    let run_dir = daemon_run_dir(&home);
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::set_permissions(
        &run_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let target = daemon_socket(&home);
    sudo(&["mv", sock.to_str().unwrap(), target.to_str().unwrap()]);
    sudo(&[
        "chown",
        &envcloak_sys::effective_uid().to_string(),
        target.to_str().unwrap(),
    ]);

    let unlock = run(
        &home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass_file, true)],
    );
    let create = run(
        &home,
        &["vault", "create", "--passphrase-fd", "3", "--kit-fd", "4"],
        &[(3, &pass_file, true), (4, &kit_file, false)],
    );
    let status = run(&home, &["status"], &[]);
    for out in [&unlock, &create, &status] {
        assert_eq!(out.status.code(), Some(1));
        let err = stderr(out);
        assert!(err.starts_with("envcloak: daemon_unverified:"), "{err}");
        assert!(err.contains("runs as another user"), "{err}");
        assert_no_canary(&out.stdout, &cs);
        assert_no_canary(&out.stderr, &cs);
    }
    assert_eq!(std::fs::read(&kit_file).unwrap(), b"", "no kit was written");

    let _ = Command::new("sudo")
        .args(["-n", "kill", &squatter.id().to_string()])
        .status();
    let _ = squatter.wait();
    let got = sudo(&["cat", record.to_str().unwrap()]);
    let counts = String::from_utf8_lossy(&got.stdout).into_owned();
    sudo(&["rm", "-rf", dir_s]);
    let _ = std::fs::remove_file(&target);
    // Each command connected, looked at the peer, and sent nothing.
    let counts: Vec<&str> = counts.lines().collect();
    assert_eq!(counts.len(), 3, "{counts:?}");
    assert!(counts.iter().all(|c| *c == "0"), "{counts:?}");
}
