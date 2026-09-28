//! Process information and the ancestry walk (SPEC §10a, §10b "Root
//! selection"; T8). Real processes: this test process, `launchd` or
//! `init`, and `python3` children that connect to a socket, some in a new
//! session or on a pseudo-terminal of their own. The walk's re-validation
//! is tested against a process table whose answers change between reads,
//! and the argument parsers against arbitrary bytes.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader};
use std::os::fd::AsFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use envcloak_sys::{
    AncestryError, MAX_ARGV, MAX_ARGV_BYTES, PeerIdentity, PeerSource, ProcInfo, ProcessTable,
    StartTime, ancestry, ancestry_in, effective_uid, parse_cmdline, parse_proc_stat,
    parse_procargs2, peer_identity, proc_argv, proc_info, process_start_time,
};
use proptest::prelude::*;

fn own_pid() -> i32 {
    i32::try_from(std::process::id()).unwrap()
}

fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ecq")
        .tempdir_in("/tmp")
        .unwrap()
}

/// A `python3` child. `how` is `plain`, `setsid` (a new session, no
/// terminal) or `pty` (a new session whose controlling terminal is a new
/// pseudo-terminal). It connects to `sock` when given, prints `ready` and
/// waits for its stdin to close. Killed and reaped on drop.
struct Py {
    child: Child,
    pid: i32,
}

const PY: &str = r#"import os, pty, socket, sys
how, sock = sys.argv[1], sys.argv[2]
def run():
    if sock:
        s = socket.socket(socket.AF_UNIX)
        s.connect(sock)
    print('ready %d' % os.getpid(), flush=True)
    sys.stdin.read()
if how == 'setsid':
    os.setsid()
    run()
elif how == 'pty':
    r, w = os.pipe()
    pid, fd = pty.fork()
    if pid == 0:
        os.close(r)
        os.dup2(w, 1)
        os.dup2(os.open('/dev/null', os.O_RDONLY), 0)
        run()
        sys.exit(0)
    os.close(w)
    out = os.fdopen(r)
    print(out.readline().strip(), flush=True)
    sys.stdin.read()
    os.kill(pid, 9)
else:
    run()
"#;

impl Py {
    fn start(how: &str, sock: Option<&Path>, extra: &[&str]) -> Self {
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(PY)
            .arg(how)
            .arg(sock.map_or(OsString::new(), |p| p.as_os_str().to_owned()))
            .args(extra)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
            .env("ENVCLOAK_PROC_TEST_ENV", "never-an-argument")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let pid = line
            .trim()
            .strip_prefix("ready ")
            .unwrap_or_else(|| panic!("unexpected: {line:?}"))
            .parse()
            .unwrap();
        Py { child, pid }
    }
}

impl Drop for Py {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn listener() -> (tempfile::TempDir, PathBuf, UnixListener) {
    let dir = short_dir();
    let path = dir.path().join("s.sock");
    let l = UnixListener::bind(&path).unwrap();
    (dir, path, l)
}

fn file_name(p: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    p.file_name().unwrap().as_bytes().to_vec()
}

#[test]
fn this_process_is_reported_as_the_kernel_sees_it() {
    let me = proc_info(own_pid()).unwrap();
    assert_eq!(me.pid, own_pid());
    assert_eq!(
        me.ppid,
        i32::try_from(std::os::unix::process::parent_id()).unwrap()
    );
    assert_eq!(me.start_time, process_start_time(own_pid()).unwrap());
    assert_eq!(me.uid, effective_uid());
    assert!(me.argv.is_none());
    let exe = me.exe.as_ref().expect("this process's own executable");
    let real = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(std::fs::canonicalize(&exe.path).unwrap(), real);
    // The command name is the start of the executable's file name.
    use std::os::unix::ffi::OsStrExt;
    let comm = me.comm.as_bytes();
    assert!(
        !comm.is_empty() && file_name(&real).starts_with(comm),
        "{me:?}"
    );
    if cfg!(target_os = "linux") {
        let m = std::fs::metadata(&real).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(exe.file, Some((m.dev(), m.ino())));
        assert!(exe.signature.is_none());
    } else {
        assert!(exe.file.is_none());
    }
    // Stable while the process lives.
    assert_eq!(proc_info(own_pid()).unwrap(), me);
}

#[test]
fn the_top_of_the_tree_and_missing_processes() {
    // pid 1 runs as root: macOS's proc_pidinfo refuses it, kinfo_proc
    // does not.
    let init = proc_info(1).unwrap();
    assert_eq!(init.ppid, 0);
    assert_eq!(init.uid, 0);
    assert!(init.start_time <= process_start_time(own_pid()).unwrap());
    if cfg!(target_os = "macos") {
        let exe = init.exe.unwrap();
        assert_eq!(exe.path, Path::new("/sbin/launchd"));
        let sig = exe.signature.expect("launchd's platform signature");
        assert_eq!(sig.identifier, "com.apple.xpc.launchd");
        assert_eq!(sig.team_id, None);
        // Another user's arguments are refused, not misread.
        assert!(proc_argv(1).is_err());
    }
    for pid in [i32::MAX, 0, -1] {
        let err = proc_info(pid).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{pid}: {err}");
    }
}

#[test]
fn sessions_and_terminals() {
    let plain = Py::start("plain", None, &[]);
    let p = proc_info(plain.pid).unwrap();
    assert_eq!(p.ppid, own_pid());
    assert_eq!(
        p.sid,
        proc_info(own_pid()).unwrap().sid,
        "a child keeps its session"
    );

    let detached = Py::start("setsid", None, &[]);
    let d = proc_info(detached.pid).unwrap();
    assert_eq!(d.sid, Some(detached.pid), "setsid makes it the leader");
    assert!(!d.controlling_tty, "a new session has no terminal");

    let term = Py::start("pty", None, &[]);
    let t = proc_info(term.pid).unwrap();
    assert_eq!(t.sid, Some(term.pid));
    assert!(
        t.controlling_tty,
        "pty.fork gives the child a controlling terminal"
    );
    assert_ne!(t.ppid, own_pid(), "its parent is the python3 driver");
}

#[test]
fn arguments_are_read_and_the_environment_is_not() {
    let child = Py::start("plain", None, &["--flag", "a b", ""]);
    let argv = proc_argv(child.pid).unwrap();
    let tail: Vec<&str> = argv[argv.len() - 5..]
        .iter()
        .map(|a| a.to_str().unwrap())
        .collect();
    assert_eq!(tail, ["plain", "", "--flag", "a b", ""]);
    // python3 may re-exec itself under another name; its own arguments
    // follow.
    assert!(!argv[0].is_empty());
    assert_eq!(argv[argv.len() - 7], "-c");
    assert!(
        argv[argv.len() - 6]
            .to_str()
            .unwrap()
            .starts_with("import os")
    );
    for a in &argv {
        assert!(
            !a.to_str().unwrap().contains("never-an-argument"),
            "{argv:?}"
        );
    }
}

#[test]
fn the_ancestry_of_a_connected_peer_reaches_the_top() {
    let (_dir, path, l) = listener();
    let child = Py::start("plain", Some(&path), &[]);
    let (server, _) = l.accept().unwrap();
    let peer = peer_identity(server.as_fd()).unwrap();
    assert_eq!(peer.pid, child.pid);

    let chain = ancestry(&peer, envcloak_sys::MAX_ANCESTRY, &|p| p.pid == child.pid).unwrap();
    assert_eq!(chain[0].pid, child.pid);
    assert_eq!(chain[0].start_time, peer.start_time);
    assert!(chain[0].argv.as_ref().is_some_and(|a| !a.is_empty()));
    assert_eq!(chain[1].pid, own_pid());
    assert!(chain[1].argv.is_none(), "arguments only where asked");
    for w in chain.windows(2) {
        assert_eq!(w[0].ppid, w[1].pid);
        assert!(w[1].start_time <= w[0].start_time);
    }
    let top = chain.last().unwrap();
    assert_eq!(top.ppid, 0, "{chain:?}");

    // Cut at a depth.
    let two = ancestry(&peer, 2, &|_| false).unwrap();
    assert_eq!(two.len(), 2);
    assert_eq!(two[1].pid, own_pid());
    assert_eq!(ancestry(&peer, 0, &|_| false).unwrap().len(), 1);

    // The peer must be the process the socket reported.
    let wrong = PeerIdentity {
        start_time: StartTime::from_raw(peer.start_time.raw() + 1),
        ..peer
    };
    assert_eq!(
        ancestry(&wrong, 8, &|_| false).unwrap_err(),
        AncestryError::PeerGone
    );
    drop(child);
    drop(server);
    // Once it exits, it is gone.
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while proc_info(peer.pid).is_ok() && std::time::Instant::now() < end {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(
        ancestry(&peer, 8, &|_| false).unwrap_err(),
        AncestryError::PeerGone
    );
}

/// A process table whose answers a test scripts: each pid's answers in
/// order, the last one repeated.
#[derive(Default)]
struct Scripted {
    answers: HashMap<i32, Vec<io::Result<ProcInfo>>>,
    reads: HashMap<i32, usize>,
    argv_reads: Vec<i32>,
}

fn info(pid: i32, ppid: i32, start: u64) -> ProcInfo {
    ProcInfo {
        pid,
        ppid,
        start_time: StartTime::from_raw(start),
        uid: 501,
        sid: Some(10),
        controlling_tty: true,
        comm: OsString::from("p"),
        exe: None,
        argv: None,
    }
}

impl Scripted {
    fn with(mut self, answers: Vec<io::Result<ProcInfo>>) -> Self {
        let pid = answers
            .iter()
            .find_map(|a| a.as_ref().ok().map(|p| p.pid))
            .unwrap_or(-1);
        self.answers.insert(pid, answers);
        self
    }

    fn missing(mut self, pid: i32) -> Self {
        self.answers
            .insert(pid, vec![Err(io::ErrorKind::NotFound.into())]);
        self
    }
}

impl ProcessTable for Scripted {
    fn info(&mut self, pid: i32) -> io::Result<ProcInfo> {
        let n = self.reads.entry(pid).or_default();
        let answers = self.answers.get(&pid).ok_or(io::ErrorKind::NotFound)?;
        let a = &answers[(*n).min(answers.len() - 1)];
        *n += 1;
        match a {
            Ok(p) => Ok(p.clone()),
            Err(e) => Err(e.kind().into()),
        }
    }

    fn argv(&mut self, pid: i32) -> io::Result<Vec<OsString>> {
        self.argv_reads.push(pid);
        if pid == 30 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(vec![OsString::from(format!("prog{pid}"))])
    }
}

fn peer(pid: i32, start: u64) -> PeerIdentity {
    PeerIdentity {
        uid: 501,
        pid,
        start_time: StartTime::from_raw(start),
        pidversion: None,
        source: PeerSource::PeerCred,
    }
}

/// 40 (the peer) -> 30 -> 20 -> 1 -> 0.
fn steady() -> Scripted {
    Scripted::default()
        .with(vec![Ok(info(40, 30, 400))])
        .with(vec![Ok(info(30, 20, 300))])
        .with(vec![Ok(info(20, 1, 200))])
        .with(vec![Ok(info(1, 0, 100))])
}

#[test]
fn a_steady_chain_is_walked_once_and_read_again() {
    let mut t = steady();
    let chain = ancestry_in(&mut t, &peer(40, 400), 64, &|p| p.pid != 20).unwrap();
    let pids: Vec<i32> = chain.iter().map(|p| p.pid).collect();
    assert_eq!(pids, [40, 30, 20, 1]);
    // Each process read twice: the walk and the re-validation.
    assert!(t.reads.values().all(|n| *n == 2), "{:?}", t.reads);
    assert_eq!(t.argv_reads, [40, 30, 1]);
    assert_eq!(
        chain[0].argv.as_deref(),
        Some(&[OsString::from("prog40")][..])
    );
    assert_eq!(chain[1].argv, None, "a refused read leaves None");
    assert_eq!(chain[2].argv, None, "not asked for");
}

#[test]
fn an_ancestor_whose_start_time_changes_fails_revalidation() {
    // pid 20 exits during the walk and its pid is taken by a process that
    // (as far as the table says) started at another time.
    let mut t = steady().with(vec![Ok(info(20, 1, 200)), Ok(info(20, 1, 250))]);
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
        AncestryError::Changed
    );
}

#[test]
fn a_reparented_or_resessioned_link_fails_revalidation() {
    // 30 is reparented to 1 after the walk read it.
    let mut t = steady().with(vec![Ok(info(30, 20, 300)), Ok(info(30, 1, 300))]);
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
        AncestryError::Changed
    );
    // 30 leaves its session.
    let mut moved = info(30, 20, 300);
    moved.sid = Some(30);
    let mut t = steady().with(vec![Ok(info(30, 20, 300)), Ok(moved)]);
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
        AncestryError::Changed
    );
    // The peer's session loses its terminal.
    let mut lost = info(40, 30, 400);
    lost.controlling_tty = false;
    let mut t = steady().with(vec![Ok(info(40, 30, 400)), Ok(lost)]);
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
        AncestryError::Changed
    );
}

#[test]
fn a_parent_newer_than_its_child_is_a_reused_pid() {
    let mut t = steady().with(vec![Ok(info(20, 1, 350))]);
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
        AncestryError::Changed
    );
}

#[test]
fn a_parent_that_vanished_mid_walk_is_a_change() {
    let mut t = steady().missing(20);
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
        AncestryError::Changed
    );
    // An ancestor that exits before the re-validation.
    let mut t = steady().with(vec![
        Ok(info(30, 20, 300)),
        Err(io::ErrorKind::NotFound.into()),
    ]);
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
        AncestryError::Changed
    );
}

#[test]
fn the_peer_must_be_the_process_that_connected() {
    let mut t = steady();
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 401), 64, &|_| false).unwrap_err(),
        AncestryError::PeerGone
    );
    let mut t = steady().missing(40);
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
        AncestryError::PeerGone
    );
    // It exits before the re-validation.
    let mut t = steady().with(vec![
        Ok(info(40, 30, 400)),
        Err(io::ErrorKind::NotFound.into()),
    ]);
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
        AncestryError::PeerGone
    );
    // Other errors are passed on by kind.
    let mut t = steady().with(vec![
        Ok(info(30, 20, 300)),
        Err(io::ErrorKind::PermissionDenied.into()),
    ]);
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
        AncestryError::Io(io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn an_orphan_walks_straight_to_the_top() {
    // A process reparented to init: its chain is short, and consistent.
    let mut t = Scripted::default()
        .with(vec![Ok(info(40, 1, 400))])
        .with(vec![Ok(info(1, 0, 100))]);
    let chain = ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap();
    assert_eq!(chain.iter().map(|p| p.pid).collect::<Vec<_>>(), [40, 1]);
}

#[test]
fn debug_output_names_no_argument() {
    let mut p = info(40, 30, 400);
    p.argv = Some(vec![OsString::from("--token=hunter2-not-a-secret")]);
    let shown = format!("{p:?}");
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(shown.contains("argc: Some(1)"), "{shown}");
}

/// A `KERN_PROCARGS2` buffer: argc, the executable's path, padding, then
/// the arguments and the environment, each NUL-terminated.
fn procargs(argc: usize, path: &[u8], pad: usize, args: &[Vec<u8>], env: &[Vec<u8>]) -> Vec<u8> {
    let mut b = i32::try_from(argc).unwrap().to_ne_bytes().to_vec();
    b.extend_from_slice(path);
    b.push(0);
    b.extend(std::iter::repeat_n(0u8, pad));
    for s in args.iter().chain(env) {
        b.extend_from_slice(s);
        b.push(0);
    }
    b
}

fn no_nul() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(1u8..=255, 0..40)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Any bytes: no panic, and the caps hold.
    #[test]
    fn procargs2_never_panics(buf in prop::collection::vec(any::<u8>(), 0..600)) {
        if let Some(args) = parse_procargs2(&buf) {
            prop_assert!(args.len() <= MAX_ARGV);
            let total: usize = args.iter().map(|a| a.len()).sum();
            prop_assert!(total <= MAX_ARGV_BYTES);
        }
        let args = parse_cmdline(&buf);
        prop_assert!(args.len() <= MAX_ARGV);
        let _ = parse_proc_stat(&buf);
    }

    /// Well-formed buffers give exactly their arguments, and never an
    /// environment string, whatever the path, padding and strings. (An
    /// empty `argv[0]` cannot be told from padding; exec'd programs have a
    /// name there.)
    #[test]
    fn procargs2_gives_the_arguments_only(
        path in no_nul(),
        pad in 0usize..9,
        first in prop::collection::vec(1u8..=255, 1..40),
        rest in prop::collection::vec(no_nul(), 0..8),
        env in prop::collection::vec(no_nul(), 0..8),
    ) {
        use std::os::unix::ffi::OsStringExt;
        let mut args = vec![first];
        args.extend(rest);
        let b = procargs(args.len(), &path, pad, &args, &env);
        let want: Vec<OsString> = args.iter().map(|a| OsString::from_vec(a.clone())).collect();
        prop_assert_eq!(parse_procargs2(&b).unwrap(), want);
    }

    /// A buffer cut before its last argument's NUL is refused: it never
    /// looks complete.
    #[test]
    fn truncated_procargs2_is_refused(
        args in prop::collection::vec(prop::collection::vec(1u8..=255, 1..20), 1..6),
        cut in 0usize..200,
    ) {
        let b = procargs(args.len(), b"/bin/x", 2, &args, &[]);
        let cut = cut.min(b.len() - 1);
        prop_assert!(parse_procargs2(&b[..cut]).is_none());
    }
}
