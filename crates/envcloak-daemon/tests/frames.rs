//! Gate 32's frame half (SPEC §10a "Bounds"): frames over 1 MiB are
//! rejected, memory stays bounded under a flood of connections and
//! partial frames, and a frame that stalls is dropped at its deadline.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use common::{client, closed, error_kind, raw, read_json, rss_kib, run_paths, send_json, start};
use envcloak_ipc::MAX_FRAME;
use envcloak_ipc::view::VaultState;
use envcloak_testkit::TestHome;
use serde_json::json;

fn header(len: usize) -> [u8; 4] {
    u32::try_from(len).unwrap().to_be_bytes()
}

#[test]
fn a_frame_over_the_limit_is_refused_and_the_connection_closed() {
    let home = TestHome::new();
    let _d = start(&home);
    for len in [MAX_FRAME + 1, u32::MAX as usize] {
        let mut s = raw(&home);
        s.write_all(&header(len)).unwrap();
        // Whatever follows is never read as a request.
        let _ = s.write_all(br#"{"jsonrpc":"2.0","id":1,"method":"lock"}"#);
        let r = read_json(&mut s).unwrap();
        assert_eq!(error_kind(&r), "frame_too_large");
        assert!(r["id"].is_null());
        assert!(closed(&mut s));
    }
    let mut s = raw(&home);
    s.write_all(&header(0)).unwrap();
    assert_eq!(error_kind(&read_json(&mut s).unwrap()), "invalid_request");
    assert!(closed(&mut s));

    // A frame of exactly the limit is read (and is not a valid request).
    let mut s = raw(&home);
    let mut body = vec![b' '; MAX_FRAME];
    body[..2].copy_from_slice(b"{}");
    s.write_all(&header(MAX_FRAME)).unwrap();
    s.write_all(&body).unwrap();
    assert_eq!(error_kind(&read_json(&mut s).unwrap()), "invalid_request");
    send_json(
        &mut s,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "status"}),
    );
    assert_eq!(read_json(&mut s).unwrap()["id"], 2);

    assert_eq!(
        client(&home).status().unwrap().vault.state,
        VaultState::Absent
    );
}

/// Thousands of oversized headers, then more connections than the daemon
/// serves, each holding half a megabyte of an unfinished frame: the
/// daemon's resident memory stays within the bound its connection cap
/// sets, connections past the cap are closed at once, and it keeps
/// serving afterwards.
#[test]
fn memory_stays_bounded_under_a_flood() {
    let home = TestHome::new();
    let d = start(&home);
    client(&home).status().unwrap();
    let before = rss_kib(d.pid());

    // The kernel's listen backlog refuses connections the daemon has not
    // accepted yet (macOS says ECONNREFUSED); wait and try again.
    let connect = || {
        for _ in 0..1000 {
            match UnixStream::connect(run_paths(&home).socket) {
                Ok(s) => return s,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("{e}"),
            }
        }
        panic!("the daemon stopped accepting connections");
    };
    for _ in 0..2000 {
        let mut s = connect();
        let _ = s.write_all(&header(MAX_FRAME + 1));
    }

    let half = vec![b'x'; MAX_FRAME / 2];
    let mut held = Vec::new();
    for _ in 0..96 {
        let mut s = connect();
        s.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        s.write_all(&header(MAX_FRAME)).unwrap();
        // Past the cap the daemon closes the connection, so the write may
        // fail; that is the point.
        let _ = s.write_all(&half);
        held.push(s);
    }
    std::thread::sleep(Duration::from_millis(500));
    let during = rss_kib(d.pid());
    eprintln!("resident memory: {before} KiB before, {during} KiB during the flood");
    // 32 served connections at up to 1.5 MiB each (a body buffer grown to
    // 1 MiB while the half it replaced is wiped), plus allocator slack.
    // Without the cap, 96 connections would take about three times that.
    assert!(
        during < before + 80 * 1024,
        "resident memory grew from {before} KiB to {during} KiB"
    );
    let refused = held.iter_mut().map(closed).filter(|c| *c).count();
    assert!(
        refused >= 96 - 32,
        "only {refused} connections were refused"
    );

    drop(held);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        client(&home).status().unwrap().vault.state,
        VaultState::Absent
    );
    let log = d.log();
    assert!(log.contains("connection limit reached"), "{log}");
}

/// A frame whose body stops arriving is dropped once its deadline passes,
/// freeing the connection.
#[test]
fn a_frame_that_stalls_is_dropped_at_its_deadline() {
    let home = TestHome::new();
    let _d = start(&home);
    let mut s = raw(&home);
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.write_all(&header(100)).unwrap();
    s.write_all(b"{\"jsonrpc\":").unwrap();
    let t = Instant::now();
    assert!(closed(&mut s));
    let waited = t.elapsed();
    assert!(
        waited >= Duration::from_secs(8) && waited < Duration::from_secs(25),
        "{waited:?}"
    );
}
