//! Integration tests for `envcloak-poll::tls` (`SPEC §8`, `§11`, `D4-04`,
//! `D4-20`, `D4-27`, task `M4-06a`, gate `11` and `s3`):
//! 1. Release-feature test: a release build of `envcloak-poll` (without the
//!    `testing` feature) contains neither `TestRoots` nor
//!    `TEST_ROOTS_SENTINEL`, whereas the `testing` build contains the sentinel
//!    as a positive control.
//! 2. TLS handshake and HTTPS round-trip under a run-time `TestCa` succeed when
//!    the client trusts that CA (`TestRoots::new(ca_a)`), and fail at the TLS
//!    handshake before any application byte is sent when the server presents:
//!    - a certificate issued by a foreign CA (`ca_b`),
//!    - a certificate issued by `ca_a` for a different hostname (`wrong.example.test`),
//!    - or when the client uses `ReleaseRoots` (`rustls-platform-verifier`),
//!      which never trusts a run-time test CA.
//! 3. `scripts/check-daemon-tree.sh` confirms `cargo tree -p envcloakd -e
//!    normal,build` holds no `envcloak-poll`, `ureq`, `rustls` or `ring`.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use envcloak_poll::tls::{
    ReleaseRoots, TEST_ROOTS_SENTINEL, TestCa, TestRoots, tls_config, ureq_tls_config,
};
use rustls::pki_types::ServerName;

fn holds_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Starts a single-connection local TLS server on `127.0.0.1:0` with `server_cfg`.
///
/// Counts how many decrypted application bytes the client sent after a
/// successful TLS handshake. If the TLS handshake fails, `app_bytes_received`
/// stays `0`.
fn spawn_one_shot_tls_server(
    server_cfg: Arc<rustls::ServerConfig>,
    response_http: &'static [u8],
) -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    std::thread::JoinHandle<Result<(), String>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let app_bytes = Arc::new(AtomicUsize::new(0));
    let app_bytes_clone = Arc::clone(&app_bytes);

    let handle = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().map_err(|e| e.to_string())?;
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
        let mut conn =
            rustls::ServerConnection::new(server_cfg).map_err(|e| format!("server init: {e}"))?;

        while conn.is_handshaking() {
            if let Err(e) = conn.complete_io(&mut tcp) {
                return Err(format!("handshake failed: {e}"));
            }
        }

        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
        let mut buf = [0u8; 1024];
        match stream.read(&mut buf) {
            Ok(n) if n > 0 => {
                app_bytes_clone.fetch_add(n, Ordering::SeqCst);
                stream
                    .write_all(response_http)
                    .map_err(|e| format!("write failed: {e}"))?;
                let _ = stream.flush();
                conn.send_close_notify();
                let _ = conn.complete_io(&mut tcp);
                Ok(())
            }
            Ok(_) => Ok(()),
            Err(e) => Err(format!("read after handshake failed: {e}")),
        }
    });

    (addr, app_bytes, handle)
}

#[test]
fn test_roots_accepts_matching_ca_and_rejects_foreign_ca_and_wrong_san_and_release_roots() {
    let ca_a = TestCa::from_seed([0x11; 32], "EnvCloak Test CA A");
    let ca_b = TestCa::from_seed([0x22; 32], "EnvCloak Foreign CA B");

    // 1. Positive control: server cert signed by CA A for `localhost` & `127.0.0.1`,
    //    verified by a client configured with `TestRoots::new(ca_a)`.
    let server_cfg_a = Arc::new(
        ca_a.server_config([0x33; 32], &["localhost"], &[[127, 0, 0, 1]])
            .unwrap(),
    );
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{\"ok\":true}\n";
    let (addr_ok, bytes_ok, handle_ok) = spawn_one_shot_tls_server(server_cfg_a.clone(), response);

    let agent_a = ureq::Agent::config_builder()
        .tls_config(ureq_tls_config(TestRoots::new(ca_a.clone())))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .new_agent();

    let url_ok = format!("https://localhost:{}/v1/balance", addr_ok.port());
    let mut resp = agent_a
        .get(&url_ok)
        .header("Authorization", "Bearer test-token")
        .call()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.body_mut().read_to_string().unwrap();
    assert_eq!(body.trim(), "{\"ok\":true}");
    assert!(handle_ok.join().unwrap().is_ok());
    assert!(
        bytes_ok.load(Ordering::SeqCst) > 0,
        "matching CA must receive the request after TLS handshake"
    );

    // 2. Foreign CA: server cert signed by CA B, client trusts only CA A.
    //    Must fail TLS verification with zero application bytes received!
    let server_cfg_b = Arc::new(
        ca_b.server_config([0x44; 32], &["localhost"], &[[127, 0, 0, 1]])
            .unwrap(),
    );
    let (addr_foreign, bytes_foreign, handle_foreign) =
        spawn_one_shot_tls_server(server_cfg_b, response);
    let url_foreign = format!("https://localhost:{}/v1/balance", addr_foreign.port());
    let res_foreign = agent_a
        .get(&url_foreign)
        .header("Authorization", "Bearer secret-must-never-leave")
        .call();
    assert!(
        res_foreign.is_err(),
        "foreign CA certificate must fail TLS handshake"
    );
    let server_res_foreign = handle_foreign.join().unwrap();
    assert!(
        server_res_foreign.is_err(),
        "server must observe handshake failure on foreign CA"
    );
    assert_eq!(
        bytes_foreign.load(Ordering::SeqCst),
        0,
        "zero application bytes may be sent when foreign CA fails handshake"
    );

    // 3. Wrong SAN hostname: server cert signed by CA A for `other.example.test`
    //    only, client connects to `localhost`. Must fail hostname verification
    //    with zero application bytes!
    let server_cfg_wrong_san = Arc::new(
        ca_a.server_config([0x55; 32], &["other.example.test"], &[])
            .unwrap(),
    );
    let (addr_san, bytes_san, handle_san) =
        spawn_one_shot_tls_server(server_cfg_wrong_san, response);
    let url_san = format!("https://localhost:{}/v1/balance", addr_san.port());
    let res_san = agent_a
        .get(&url_san)
        .header("Authorization", "Bearer secret-must-never-leave")
        .call();
    assert!(
        res_san.is_err(),
        "mismatched Subject Alternative Name must fail TLS verification"
    );
    let _ = handle_san.join().unwrap();
    assert_eq!(
        bytes_san.load(Ordering::SeqCst),
        0,
        "zero application bytes may be sent when SAN verification fails"
    );

    // 4. ReleaseRoots (`rustls-platform-verifier`): client configured with
    //    `ReleaseRoots` rejects the run-time test CA (`ca_a`) with zero
    //    application bytes!
    let (addr_rel, bytes_rel, handle_rel) = spawn_one_shot_tls_server(server_cfg_a, response);
    let client_cfg_release = Arc::new(tls_config(ReleaseRoots).unwrap());
    let mut tcp = std::net::TcpStream::connect(addr_rel).unwrap();
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut client_conn = rustls::ClientConnection::new(client_cfg_release, server_name).unwrap();
    let mut handshake_err = None;
    while client_conn.is_handshaking() {
        if let Err(e) = client_conn.complete_io(&mut tcp) {
            handshake_err = Some(e);
            break;
        }
    }
    assert!(
        handshake_err.is_some(),
        "ReleaseRoots (platform verifier) must reject a run-time TestCa certificate"
    );
    let _ = handle_rel.join().unwrap();
    assert_eq!(
        bytes_rel.load(Ordering::SeqCst),
        0,
        "ReleaseRoots must send zero application bytes to a test-CA server"
    );
}

#[test]
fn release_build_of_envcloak_poll_has_no_test_roots_symbol() {
    // 1. Positive control: the current test binary (built with `testing`)
    //    calls `TestRoots::new` and holds both `TEST_ROOTS_SENTINEL` and
    //    `TestRoots`.
    let ca = TestCa::from_seed([0x77; 32], "Sentinel Control CA");
    let roots = TestRoots::new(ca);
    let _cfg = tls_config(roots).unwrap();

    let current_exe = std::env::current_exe().unwrap();
    let current_bytes = std::fs::read(&current_exe).unwrap();
    assert!(
        holds_subslice(&current_bytes, TEST_ROOTS_SENTINEL),
        "positive control: test binary must contain TEST_ROOTS_SENTINEL"
    );
    assert!(
        holds_subslice(&current_bytes, b"TestRoots"),
        "positive control: test binary must contain TestRoots symbol"
    );

    // 2. Build `envcloak-poll` with default features (no `testing`) using the
    //    workspace target directory so already-compiled dependencies are reused,
    //    and inspect the produced `libenvcloak_poll.rlib`.
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().unwrap().parent().unwrap();
    // `current_exe` is `<target_dir>/debug/deps/tls-<hash>`.
    let profile_dir = current_exe.parent().unwrap().parent().unwrap();
    let target_dir = profile_dir.parent().unwrap();

    let out = Command::new(env!("CARGO"))
        .current_dir(root)
        .env("CARGO_TARGET_DIR", target_dir)
        .args(["build", "--locked", "-p", "envcloak-poll"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "cargo build -p envcloak-poll failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rlib_path = profile_dir.join("libenvcloak_poll.rlib");
    assert!(
        rlib_path.is_file(),
        "expected default-feature artifact at {}",
        rlib_path.display()
    );
    let rlib_bytes = std::fs::read(&rlib_path).unwrap();
    assert!(
        !holds_subslice(&rlib_bytes, TEST_ROOTS_SENTINEL),
        "non-testing libenvcloak_poll.rlib must not contain TEST_ROOTS_SENTINEL"
    );

    // Also inspect the object symbol table via `nm`: the test binary defines
    // `TestRoots` symbols (`TestRoots::new`), whereas the non-testing `.rlib`
    // defines `tls_config` / `ureq_tls_config` and zero `TestRoots` or
    // `TestCa` symbols.
    let nm_test = Command::new("nm").arg(&current_exe).output().unwrap();
    let nm_test_stdout = String::from_utf8_lossy(&nm_test.stdout);
    assert!(
        nm_test_stdout.contains("TestRoots"),
        "positive control: nm on test binary must list TestRoots symbols"
    );

    let nm_rlib = Command::new("nm").arg(&rlib_path).output().unwrap();
    let nm_rlib_stdout = String::from_utf8_lossy(&nm_rlib.stdout);
    assert!(
        nm_rlib_stdout.contains("tls_config"),
        "positive control: nm on libenvcloak_poll.rlib must list tls_config symbol"
    );
    assert!(
        !nm_rlib_stdout.contains("TestRoots") && !nm_rlib_stdout.contains("TestCa"),
        "non-testing libenvcloak_poll.rlib object symbols must not contain TestRoots or TestCa"
    );
}

#[test]
fn check_daemon_tree_confirms_envcloakd_holds_no_http_or_tls_crates() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().unwrap().parent().unwrap();
    let script = root.join("scripts/check-daemon-tree.sh");

    let out = Command::new("bash")
        .arg(&script)
        .arg(root)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "check-daemon-tree.sh failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Mutation check: simulate a `cargo` wrapper whose `envcloakd` tree output
    // includes `ureq v3.4.2` or `envcloak-poll v0.1.0` and verify
    // `check-daemon-tree.sh` fails.
    let fake_dir = tempfile::Builder::new()
        .prefix("ec-fake-cargo-")
        .tempdir_in(manifest_dir)
        .unwrap();
    let fake_cargo = fake_dir.path().join("fake-cargo.sh");
    std::fs::write(
        &fake_cargo,
        "#!/usr/bin/env bash\necho 'envcloakd v0.1.0'\necho '└── envcloak-poll v0.1.0'\necho '    └── ureq v3.4.2'\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = std::fs::metadata(&fake_cargo).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_cargo, perms).unwrap();
    }

    let bad = Command::new("bash")
        .env("CARGO", &fake_cargo)
        .arg(&script)
        .arg(root)
        .output()
        .unwrap();
    assert!(
        !bad.status.success(),
        "check-daemon-tree.sh must fail when envcloakd tree contains envcloak-poll or ureq"
    );
}
