//! Gate 32's frame half (SPEC §10a "Bounds"): frames over 1 MiB are
//! rejected, memory stays bounded under a flood of connections and
//! partial frames, and a frame that stalls is dropped at its deadline.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use common::{
    client, closed, error_kind, raw, read_json, rss_kib, run_paths, send_json, start,
    status_when_free,
};
use envcloak_ipc::MAX_FRAME;
use envcloak_ipc::view::VaultState;
use envcloak_testkit::{TEST_PATH, TestHome};
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

/// A `python3` process that opens `argv[2]` connections to the socket
/// `argv[1]`, starts a frame of 1 MiB on each and sends `argv[3]` bytes of
/// it, then prints `ready`. On a line from its stdin it prints how many of
/// those connections the daemon closed, then waits for its stdin to close.
const FLOODER: &str = r#"import socket, struct, sys, time
path, n, half = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
socks = []
for _ in range(n):
    for _ in range(1000):
        s = socket.socket(socket.AF_UNIX)
        try:
            s.connect(path)
            break
        except (ConnectionRefusedError, BlockingIOError):
            s.close()
            time.sleep(0.005)
    else:
        sys.exit('the daemon stopped accepting connections')
    try:
        s.sendall(struct.pack('>I', 1 << 20))
        s.sendall(b'x' * half)
    except OSError:
        pass
    socks.append(s)
print('ready', flush=True)
sys.stdin.readline()
closed = 0
for s in socks:
    s.settimeout(0.2)
    try:
        closed += s.recv(1) == b''
    except ConnectionResetError:
        closed += 1
    except OSError:
        pass
print(closed, flush=True)
sys.stdin.read()
"#;

/// One flooding process (see [`FLOODER`]). Killed and reaped on drop.
struct Flooder {
    child: Child,
    out: BufReader<ChildStdout>,
}

impl Flooder {
    fn start(home: &TestHome, connections: usize, bytes: usize) -> Self {
        let mut child = Command::new("python3")
            .args(["-c", FLOODER])
            .arg(run_paths(home).socket)
            .arg(connections.to_string())
            .arg(bytes.to_string())
            .env_clear()
            .env("PATH", TEST_PATH)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        let mut f = Flooder { child, out };
        assert_eq!(line.trim(), "ready", "the flooder failed");
        f.child.stdin.as_mut().unwrap().flush().unwrap();
        f
    }

    /// How many of its connections the daemon has closed.
    fn closed(&mut self) -> usize {
        writeln!(self.child.stdin.as_mut().unwrap(), "report").unwrap();
        let mut line = String::new();
        self.out.read_line(&mut line).unwrap();
        line.trim().parse().unwrap()
    }
}

impl Drop for Flooder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Thousands of oversized headers, then more connections than the daemon
/// serves, from 12 processes that each hold 8 (as many as one process may
/// hold), each connection with half a megabyte of an unfinished frame: the
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
        // The daemon may already have closed a connection past its limits.
        let _ = s.write_all(&header(MAX_FRAME + 1));
    }
    // Served again once the flood has drained.
    status_when_free(&home);

    let mut flooders: Vec<Flooder> = (0..12)
        .map(|_| Flooder::start(&home, 8, MAX_FRAME / 2))
        .collect();
    std::thread::sleep(Duration::from_millis(500));
    let during = rss_kib(d.pid());
    eprintln!("resident memory: {before} KiB before, {during} KiB during the flood");
    // 32 served connections at up to about 2 MiB each (a body buffer grown
    // to 1 MiB while the half it replaced is wiped, a thread's stack and
    // its allocator arena), plus slack. Without the cap, 96 connections
    // would take about three times that.
    assert!(
        during < before + 96 * 1024,
        "resident memory grew from {before} KiB to {during} KiB"
    );
    let refused: usize = flooders.iter_mut().map(Flooder::closed).sum();
    assert!(
        refused >= 96 - 32,
        "only {refused} connections were refused"
    );

    drop(flooders);
    assert_eq!(status_when_free(&home).vault.state, VaultState::Absent);
    let log = d.log();
    assert!(
        log.contains("connection limit reached; closed a connection"),
        "{log}"
    );
}

/// One process may hold at most 8 connections, so a process that keeps
/// its connections open (an agent leaking them, say) cannot take every
/// place and lock the user's own `envcloak lock` and `status` out. Its
/// next connection is closed at once; another process is served; once it
/// closes one of its own, it is served again.
#[test]
fn one_process_cannot_take_every_connection() {
    let home = TestHome::new();
    let d = start(&home);
    let mut held: Vec<UnixStream> = (0..8).map(|_| raw(&home)).collect();
    // The daemon accepts in order, so the eight are counted by now.
    let mut ninth = raw(&home);
    assert!(closed(&mut ninth), "a ninth connection was served");
    let state = status_from_another_process(&home);
    assert_eq!(state, "absent");
    // Still at its limit: this process is refused again.
    assert!(closed(&mut raw(&home)));

    drop(held.pop());
    assert_eq!(status_when_free(&home).vault.state, VaultState::Absent);
    drop(held);
    let log = d.log();
    assert!(
        log.contains(&format!(
            "connection limit reached for pid {}",
            std::process::id()
        )),
        "{log}"
    );
}

/// `status` from a `python3` process: the vault's state.
fn status_from_another_process(home: &TestHome) -> String {
    let out = Command::new("python3")
        .args([
            "-c",
            "import json, socket, struct, sys\n\
             s = socket.socket(socket.AF_UNIX)\n\
             s.connect(sys.argv[1])\n\
             b = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'status'}).encode()\n\
             s.sendall(struct.pack('>I', len(b)) + b)\n\
             f = s.makefile('rb')\n\
             n = struct.unpack('>I', f.read(4))[0]\n\
             print(json.loads(f.read(n))['result']['vault']['state'])\n",
        ])
        .arg(run_paths(home).socket)
        .env_clear()
        .env("PATH", TEST_PATH)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
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

/// Review T7 open 2: a connection on which no frame starts is closed after
/// 30 seconds (the daemon's `IDLE_CONNECTION`), not 10 minutes, so
/// processes holding connections idle cannot keep the places for long.
#[test]
fn an_idle_connection_is_closed_after_30_seconds() {
    let home = TestHome::new();
    let _d = start(&home);
    let mut s = raw(&home);
    s.set_read_timeout(Some(Duration::from_secs(90))).unwrap();
    let t = Instant::now();
    assert!(closed(&mut s), "still open after {:?}", t.elapsed());
    let waited = t.elapsed();
    assert!(
        waited >= Duration::from_secs(28) && waited < Duration::from_secs(60),
        "{waited:?}"
    );
}

/// The idle bound counts from the end of each answer to the start of the
/// next frame: with a test build's override of 1 second, a connection
/// whose requests come every 400 ms stays open well past it, one that
/// goes quiet is closed after it, and a new connection is served.
#[test]
fn the_idle_bound_is_per_frame_and_closes_only_a_quiet_connection() {
    let home = TestHome::new();
    let mut cmd = Command::new(common::exe());
    home.apply(&mut cmd)
        .env(envcloak_sys::testing::IDLE_CONNECTION_MS, "1000");
    let _d = envcloak_testkit::Daemon::start_command(cmd, &[]);
    let mut live = raw(&home);
    let t = Instant::now();
    let mut id = 0;
    let mut answered = Instant::now();
    while t.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(400));
        id += 1;
        send_json(
            &mut live,
            &json!({"jsonrpc": "2.0", "id": id, "method": "status"}),
        );
        assert_eq!(read_json(&mut live).unwrap()["id"], id);
        answered = Instant::now();
    }
    assert!(id >= 3, "{id}");
    // The daemon's wait began as it wrote the last answer, just before it
    // was read here.
    assert!(closed(&mut live));
    let waited = answered.elapsed();
    assert!(
        waited >= Duration::from_millis(700) && waited < Duration::from_secs(10),
        "{waited:?}"
    );
    assert_eq!(
        client(&home).status().unwrap().vault.state,
        VaultState::Absent
    );
}

/// Whether `w`'s pipe has no read end left: a write fails (`EPIPE`),
/// tried for up to 5 seconds (the daemon drops what it closes as it
/// answers).
fn reader_gone(w: &std::os::fd::OwnedFd) -> bool {
    let mut f = std::fs::File::from(w.try_clone().unwrap());
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end {
        if f.write_all(b"x").is_err() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Descriptor passing (`SCM_RIGHTS`, M2 task M2-27): only a `run.request`
/// hands descriptors over. A descriptor sent with `status` is refused
/// `invalid_params` and closed by the daemon, and more descriptors than a
/// request hands over (five) close the connection unanswered, each of
/// them closed. "Closed" is seen from each pipe's write end once the
/// daemon held its only read end: a write fails. The positive control: a
/// pipe whose read end the test still holds takes the writes.
///
/// Mutations checked: descriptors sent with another method let through
/// (`status` is answered as usual, and holds them until the connection
/// ends); the count bound removed (five descriptors are taken with the
/// request, and it is answered).
#[test]
fn descriptors_with_another_method_or_too_many_are_refused_and_closed() {
    use std::os::fd::AsFd;
    let home = TestHome::new();
    let _d = start(&home);
    let (r, w) = envcloak_sys::pipe_cloexec().unwrap();
    let mut s = raw(&home);
    let status =
        envcloak_ipc::Frame::encode(&json!({"jsonrpc": "2.0", "id": 1, "method": "status"}))
            .unwrap();
    status.write_with_fds(&s, &[r.as_fd()]).unwrap();
    drop(r);
    assert_eq!(error_kind(&read_json(&mut s).unwrap()), "invalid_params");
    assert!(
        reader_gone(&w),
        "the descriptor sent with status stayed open"
    );
    // The connection still serves: a request without descriptors.
    send_json(
        &mut s,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "status"}),
    );
    assert_eq!(read_json(&mut s).unwrap()["id"], 2);
    let (kept_r, kept_w) = envcloak_sys::pipe_cloexec().unwrap();
    assert!(!reader_gone_quick(&kept_w), "the positive control");
    drop(kept_r);

    let pipes: Vec<_> = (0..5)
        .map(|_| envcloak_sys::pipe_cloexec().unwrap())
        .collect();
    let mut s = raw(&home);
    let request = envcloak_ipc::Frame::encode(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "run.request",
        "params": {"manifest": "/nonexistent/envcloak.toml", "argv": ["x"], "launch": "0".repeat(26),
                   "fds": ["stdin", "stdout", "lifeline"]},
    }))
    .unwrap();
    let ends: Vec<_> = pipes.iter().map(|(r, _)| r.as_fd()).collect();
    request.write_with_fds(&s, &ends).unwrap();
    let writers: Vec<_> = pipes.into_iter().map(|(_, w)| w).collect();
    assert!(
        read_json(&mut s).is_none(),
        "five descriptors were answered"
    );
    assert!(closed(&mut s));
    for (i, w) in writers.iter().enumerate() {
        assert!(reader_gone(w), "descriptor {i} of five stayed open");
    }
}

/// [`reader_gone`] without waiting: one write.
fn reader_gone_quick(w: &std::os::fd::OwnedFd) -> bool {
    std::fs::File::from(w.try_clone().unwrap())
        .write_all(b"x")
        .is_err()
}
