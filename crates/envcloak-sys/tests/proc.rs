//! Process information and the ancestry walk (SPEC §10a, §10b "Root
//! selection"; T8). Real processes: this test process, `launchd` or
//! `init`, and `python3` children that connect to a socket, some in a new
//! session or on a pseudo-terminal of their own. The walk's re-validation
//! is tested against a process table whose answers change between reads,
//! and the argument parsers against arbitrary bytes.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, BufReader};
use std::os::fd::AsFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use envcloak_sys::{
    AncestryError, Argv, ExeIdentity, MAX_ARGV, MAX_ARGV_BYTES, PROCARGS_ALIGN, PeerIdentity,
    PeerSource, ProcInfo, ProcessTable, ProcessWatch, StartTime, ancestry, ancestry_in,
    effective_uid, parse_cmdline, parse_proc_stat, parse_procargs2, parse_stat_state,
    peer_identity, proc_argv, proc_info, process_running, process_start_time, reaches_top,
    stat_state_exited,
};
use proptest::prelude::*;

fn strs(a: &Argv) -> Vec<&OsStr> {
    a.iter().collect()
}

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

const PY: &str = r#"import os, pty, socket, sys, time
how, sock = sys.argv[1], sys.argv[2]
def connect():
    if sock:
        s = socket.socket(socket.AF_UNIX)
        s.connect(sock)
        return s
def run():
    s = connect()
    print('ready %d' % os.getpid(), flush=True)
    sys.stdin.read()
if how == 'setsid':
    os.setsid()
    run()
elif how == 'pty':
    r, w = os.pipe()
    pid, fd = pty.fork()
    if pid == 0:
        # Stays alive until the driver below kills it.
        os.close(r)
        s = connect()
        os.write(w, b'ready %d\n' % os.getpid())
        time.sleep(3600)
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
        // Closing stdin ends it (and the `pty` driver kills its child);
        // kill it only if it does not end.
        drop(self.child.stdin.take());
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while matches!(self.child.try_wait(), Ok(None)) && std::time::Instant::now() < end {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
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

/// SPEC §6.1 (review finding F-35): on macOS each executable's cdhash is
/// recorded as the kernel validated it, the one `codesign` reports for the
/// running process, and two builds have two.
#[cfg(target_os = "macos")]
#[test]
fn the_cdhash_is_the_one_the_kernel_validated() {
    fn codesign_cdhash(pid: i32) -> String {
        let out = Command::new("/usr/bin/codesign")
            .args(["-d", "-vvv", &pid.to_string()])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stderr);
        text.lines()
            .find_map(|l| l.strip_prefix("CDHash="))
            .unwrap_or_else(|| panic!("no CDHash for {pid}: {text}"))
            .to_owned()
    }
    fn recorded(pid: i32) -> [u8; envcloak_sys::CDHASH_LEN] {
        let sig = proc_info(pid).unwrap().exe.unwrap().signature;
        sig.unwrap_or_else(|| panic!("{pid} has a valid signature"))
            .cdhash
            .unwrap_or_else(|| panic!("{pid} has a cdhash"))
    }
    let hex = |h: &[u8]| h.iter().map(|b| format!("{b:02x}")).collect::<String>();
    // This test binary (the linker signs it ad hoc) and launchd (another
    // user's platform binary).
    let mine = recorded(own_pid());
    assert_eq!(hex(&mine), codesign_cdhash(own_pid()));
    let launchd = recorded(1);
    assert_eq!(hex(&launchd), codesign_cdhash(1));
    assert_ne!(mine, launchd);
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
    assert_eq!(d.controlling_tty, None, "a new session has no terminal");

    let term = Py::start("pty", None, &[]);
    let t = proc_info(term.pid).unwrap();
    assert_eq!(t.sid, Some(term.pid));
    assert!(
        t.controlling_tty.is_some(),
        "pty.fork gives the child a controlling terminal"
    );
    assert_ne!(t.ppid, own_pid(), "its parent is the python3 driver");
    // Each terminal is its own device: the daemon tells an approver's
    // terminal from a requester's by it.
    let other = Py::start("pty", None, &[]);
    let o = proc_info(other.pid).unwrap();
    assert!(o.controlling_tty.is_some());
    assert_ne!(o.controlling_tty, t.controlling_tty, "two terminals");
}

#[test]
fn arguments_are_read_and_the_environment_is_not() {
    let child = Py::start("plain", None, &["--flag", "a b", ""]);
    let got = proc_argv(child.pid).unwrap();
    let argv = strs(&got);
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
            "{got:?}"
        );
    }
}

/// A process run with exactly `argv` (`argv[0]` included) and an
/// environment holding one variable, `canary`: `/usr/bin/xargs`, which
/// waits for its standard input whatever its arguments (an empty one is a
/// utility or an argument to it). The caller kills and reaps it.
fn with_argv(argv: &[&str], canary: &str) -> Child {
    use std::os::unix::process::CommandExt;
    Command::new("/usr/bin/xargs")
        .arg0(argv[0])
        .args(&argv[1..])
        .env_clear()
        .env("ENVCLOAK_PROC_TEST_ENV", canary)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// The arguments of a [`with_argv`] child, read once it runs xargs. On
/// Linux, spawning can return while the child still shares its parent's
/// memory (a vfork parent is woken before the child's new memory is
/// installed) or before exec has set the new argument area, and `/proc`
/// then shows the parent's arguments, or none.
fn argv_once_exec_is_done(child: &Child) -> Argv {
    let pid = i32::try_from(child.id()).unwrap();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let runs_xargs = proc_info(pid)
            .ok()
            .and_then(|p| p.exe)
            .is_some_and(|e| e.path.file_name() == Some("xargs".as_ref()));
        // Every case has at least argv[0]; none is a new argument area not
        // yet set.
        let argv = if runs_xargs {
            proc_argv(pid).unwrap_or_default()
        } else {
            Argv::default()
        };
        if !argv.is_empty() {
            return argv;
        }
        assert!(std::time::Instant::now() < end, "xargs did not start");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Review finding F-33: an empty `argv[0]`, or several leading empty
/// arguments, are arguments, and the environment after them is never read
/// as one.
#[test]
fn empty_arguments_are_read_as_empty_and_the_environment_is_not() {
    let canary = format!(
        "ecq-env-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    for argv in [
        &["xargs"][..],
        &[""],
        &["", ""],
        &["", "", ""],
        &["", "", "", "last"],
        &["xargs", "", "x"],
    ] {
        let mut child = with_argv(argv, &canary);
        let got = argv_once_exec_is_done(&child);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(strs(&got), argv, "{argv:?}");
        assert!(
            !got.iter().any(|a| a.to_string_lossy().contains(&canary)),
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
    assert!(reaches_top(&chain));

    // Cut at a depth, which the chain shows.
    let two = ancestry(&peer, 2, &|_| false).unwrap();
    assert_eq!(two.len(), 2);
    assert_eq!(two[1].pid, own_pid());
    assert!(!reaches_top(&two));
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
        controlling_tty: Some(0x1_0003),
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

    fn missing(self, pid: i32) -> Self {
        self.refused(pid, io::ErrorKind::NotFound)
    }

    fn refused(mut self, pid: i32, kind: io::ErrorKind) -> Self {
        self.answers.insert(pid, vec![Err(kind.into())]);
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

    fn argv(&mut self, pid: i32) -> io::Result<Argv> {
        self.argv_reads.push(pid);
        if pid == 30 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(Argv::new([format!("prog{pid}")]))
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
    assert_eq!(chain[0].argv, Some(Argv::new(["prog40"])));
    assert_eq!(chain[1].argv, None, "a refused read leaves None");
    assert_eq!(chain[2].argv, None, "not asked for");
}

#[test]
fn a_chain_cut_at_its_depth_does_not_reach_the_top() {
    for depth in 1..=3 {
        let mut t = steady();
        let chain = ancestry_in(&mut t, &peer(40, 400), depth, &|_| false).unwrap();
        assert_eq!(chain.len(), depth);
        assert!(!reaches_top(&chain), "{depth}");
        // Only what the walk kept was read.
        assert!(!t.reads.contains_key(&[40, 30, 20, 1][depth]));
    }
    let mut t = steady();
    let whole = ancestry_in(&mut t, &peer(40, 400), 4, &|_| false).unwrap();
    assert!(reaches_top(&whole));
    assert!(!reaches_top(&[]));
    // A process named as its own parent ends the walk, and is no top.
    let mut t = Scripted::default().with(vec![Ok(info(40, 40, 400))]);
    let looped = ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap();
    assert_eq!(looped.len(), 1);
    assert!(!reaches_top(&looped));
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
    lost.controlling_tty = None;
    let mut t = steady().with(vec![Ok(info(40, 30, 400)), Ok(lost)]);
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
        AncestryError::Changed
    );
}

/// An `exec` keeps a process's pid and start time: a link that ran another
/// file (its executable, or only its command name, changed), or whose uid
/// changed, between the walk and its check fails the check, and the
/// caller walks again. Arguments are not compared. Mutation checked:
/// leaving the executable and the command name out of the check fails
/// this test.
#[test]
fn an_exec_between_the_walk_and_its_check_fails_revalidation() {
    let exe = |path: &str, file: u64| {
        Some(ExeIdentity {
            path: PathBuf::from(path),
            file: Some((1, file)),
            sha256: None,
            signature: None,
        })
    };
    let with_exe = |path: &str, file: u64| {
        let mut p = info(30, 20, 300);
        p.exe = exe(path, file);
        p
    };
    let renamed = {
        let mut p = info(30, 20, 300);
        p.comm = OsString::from("q");
        p
    };
    let setuid = {
        let mut p = info(30, 20, 300);
        p.uid = 0;
        p
    };
    for (before, after) in [
        (with_exe("/bin/bash", 7), with_exe("/opt/agent", 8)),
        (with_exe("/bin/bash", 7), with_exe("/bin/bash", 9)),
        (info(30, 20, 300), renamed),
        (info(30, 20, 300), setuid),
    ] {
        let mut t = steady().with(vec![Ok(before.clone()), Ok(after.clone())]);
        assert_eq!(
            ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
            AncestryError::Changed,
            "{before:?} -> {after:?}"
        );
        assert!(!after.unchanged(&before));
    }
    // The control: the same file and name, with new arguments, passes.
    let mut t = steady().with(vec![Ok(with_exe("/bin/bash", 7))]);
    let chain = ancestry_in(&mut t, &peer(40, 400), 64, &|_| true).unwrap();
    assert!(chain[1].unchanged(&with_exe("/bin/bash", 7)));
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
    // 20 exited after 30 was read: 30 has been reparented by the time 20's
    // entry is gone.
    let mut t = steady()
        .missing(20)
        .with(vec![Ok(info(30, 20, 300)), Ok(info(30, 1, 300))]);
    assert_eq!(
        ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
        AncestryError::Changed
    );
    // 30 exited too.
    let mut t = steady().missing(20).with(vec![
        Ok(info(30, 20, 300)),
        Err(io::ErrorKind::NotFound.into()),
    ]);
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

/// Linux `/proc` mounted with `hidepid`: another user's parent cannot be
/// read (`hidepid=2` hides it, `hidepid=1` refuses its files), and its
/// child still names it. That is no change, and walking again would not
/// help.
#[test]
fn a_parent_hidden_from_the_walk_is_hidden() {
    for kind in [io::ErrorKind::NotFound, io::ErrorKind::PermissionDenied] {
        let mut t = steady().refused(20, kind);
        assert_eq!(
            ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
            AncestryError::Hidden,
            "{kind:?}"
        );
        // The peer's own parent.
        let mut t = steady().refused(30, kind);
        assert_eq!(
            ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
            AncestryError::Hidden,
            "{kind:?}"
        );
        // The peer exited meanwhile.
        let mut t = steady().refused(30, kind).with(vec![
            Ok(info(40, 30, 400)),
            Err(io::ErrorKind::NotFound.into()),
        ]);
        assert_eq!(
            ancestry_in(&mut t, &peer(40, 400), 64, &|_| false).unwrap_err(),
            AncestryError::PeerGone,
            "{kind:?}"
        );
    }
    assert!(!AncestryError::Hidden.message().is_empty());
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
    p.argv = Some(Argv::new(["--token=hunter2-not-a-secret"]));
    let shown = format!("{p:?}");
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(shown.contains("argc: Some(1)"), "{shown}");
}

/// A child of this test that exits when its standard input closes.
fn exits_on_eof() -> Child {
    Command::new("/bin/sh")
        .args(["-c", "read x"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Closes `child`'s standard input, so it exits, and waits, without
/// reaping it, until `running` says it no longer runs (at most 10 s).
fn exit_unreaped(child: &mut Child, running: &dyn Fn() -> bool) {
    drop(child.stdin.take());
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while running() {
        assert!(
            std::time::Instant::now() < end,
            "an exited, unreaped process still runs"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// A process that has exited and is not yet reaped (a zombie) keeps its
/// pid and its start time until its parent waits for it, and does not
/// run: `process_running` says so while `proc_info` still finds it with
/// that start time, and after the wait. Before it exits it runs; its pid
/// with another start time, and no pid, never run.
#[test]
fn an_exited_process_does_not_run_before_it_is_reaped() {
    let mut child = exits_on_eof();
    let pid = i32::try_from(child.id()).unwrap();
    let start = proc_info(pid).unwrap().start_time;
    assert!(process_running(pid, start));
    assert!(!process_running(pid, StartTime::from_raw(start.raw() + 1)));
    assert!(!process_running(0, start) && !process_running(-1, start));
    exit_unreaped(&mut child, &|| process_running(pid, start));
    assert_eq!(
        proc_info(pid).unwrap().start_time,
        start,
        "the zombie is still in the process table"
    );
    child.wait().unwrap();
    assert!(!process_running(pid, start));
}

/// A `ProcessWatch` (a pidfd on Linux) of a process runs until the
/// process exits, and no longer once it has exited, before it is reaped
/// (while `proc_info` still finds it) and after. A watch of the pid with
/// another start time never runs, nor one taken once the process exited.
#[test]
fn a_watch_ends_when_its_process_exits_before_it_is_reaped() {
    let mut child = exits_on_eof();
    let pid = i32::try_from(child.id()).unwrap();
    let start = proc_info(pid).unwrap().start_time;
    let watch = ProcessWatch::new(pid, start);
    assert!(watch.running());
    assert_eq!(
        watch.has_pidfd(),
        cfg!(any(target_os = "linux", target_os = "android"))
    );
    assert!(!ProcessWatch::new(pid, StartTime::from_raw(start.raw() + 1)).running());
    exit_unreaped(&mut child, &|| watch.running());
    assert_eq!(
        proc_info(pid).unwrap().start_time,
        start,
        "the zombie is still in the process table"
    );
    assert!(!ProcessWatch::new(pid, start).running());
    child.wait().unwrap();
    assert!(!watch.running());
}

/// `testing::process_memory` reads what the kernel counts for another
/// process, the positive control of the daemon's memory gate (M2-05
/// round 11): a `python3` child writes 96 MiB of anonymous memory and
/// unmaps it before it is looked at again, so what it holds then is about
/// what it held at the start, yet its peak holds the buffer; then it
/// writes another and keeps it, and holds about that much more.
#[test]
fn process_memory_keeps_a_peak_no_sample_saw() {
    const MIB: u64 = 1024;
    let mut c = Command::new("python3")
        .arg("-c")
        .arg(
            "import mmap, sys\n\
             n = 96 * 1024 * 1024\n\
             part = b'\\x01' * (1024 * 1024)\n\
             def written():\n\
             \x20   m = mmap.mmap(-1, n)\n\
             \x20   for at in range(0, n, len(part)):\n\
             \x20       m[at:at + len(part)] = part\n\
             \x20   return m\n\
             print('start', flush=True)\n\
             sys.stdin.readline()\n\
             written().close()\n\
             print('freed', flush=True)\n\
             sys.stdin.readline()\n\
             kept = written()\n\
             print('held', flush=True)\n\
             sys.stdin.readline()\n",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = i32::try_from(c.id()).unwrap();
    let mut out = BufReader::new(c.stdout.take().unwrap());
    let mut input = c.stdin.take().unwrap();
    let mut step = |want: &str| {
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), want);
        let m = envcloak_sys::testing::process_memory(pid).unwrap();
        std::io::Write::write_all(&mut input, b"\n").unwrap();
        m
    };
    let start = step("start");
    let freed = step("freed");
    let held = step("held");
    c.wait().unwrap();
    assert!(
        freed.now_kib < start.now_kib + 30 * MIB,
        "the buffer was not given back: {start:?} {freed:?}"
    );
    assert!(
        freed.peak_kib >= start.now_kib + 90 * MIB,
        "the peak missed a buffer freed between two samples: {start:?} {freed:?}"
    );
    assert!(
        held.now_kib >= start.now_kib + 90 * MIB,
        "{start:?} {held:?}"
    );
    assert!(held.peak_kib >= held.now_kib, "{held:?}");
}

#[test]
fn the_state_letter_is_read_after_the_last_parenthesis() {
    for (stat, want) in [
        (&b"42 (sh) Z 1 42 42 0 -1"[..], Some(b'Z')),
        (b"42 (sh) S 1 42", Some(b'S')),
        (b"42 (a) Z (b) R 1 2", Some(b'R')),
        (b"42 (a b) X 1", Some(b'X')),
        (b"42 (\xff) x 1", Some(b'x')),
        (b"", None),
        (b"42 sh S 1", None),
        (b"42 (sh) S", None),
        (b"42 (sh)  S 1", None),
        (b"42 (sh) SS 1", None),
        (b"42 (sh) 1 1", None),
        (b"42 (sh)\tS 1", None),
        (b"42 (sh) \xffS 1", None),
    ] {
        assert_eq!(parse_stat_state(stat), want, "{stat:?}");
    }
    for s in *b"ZXx" {
        assert!(stat_state_exited(s), "{}", s as char);
    }
    for s in *b"RSDTtIWPK" {
        assert!(!stat_state_exited(s), "{}", s as char);
    }
}

/// A `KERN_PROCARGS2` buffer as `exec` lays it out: argc, the executable's
/// path, its NUL and NULs to the next multiple of [`PROCARGS_ALIGN`], then
/// the arguments and the environment, each NUL-terminated.
fn procargs(argc: usize, path: &[u8], args: &[Vec<u8>], env: &[Vec<u8>]) -> Vec<u8> {
    let mut b = i32::try_from(argc).unwrap().to_ne_bytes().to_vec();
    b.extend_from_slice(path);
    b.push(0);
    while (b.len() - 4) % PROCARGS_ALIGN != 0 {
        b.push(0);
    }
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

    /// Well-formed buffers give exactly their arguments, empty ones
    /// included (`argv[0]` too: any `exec` may pass one), and never an
    /// environment string, whatever the path and strings.
    #[test]
    fn procargs2_gives_the_arguments_only(
        path in no_nul(),
        args in prop::collection::vec(no_nul(), 0..8),
        env in prop::collection::vec(no_nul(), 0..8),
    ) {
        use std::os::unix::ffi::OsStringExt;
        let b = procargs(args.len(), &path, &args, &env);
        let want: Vec<OsString> = args.iter().map(|a| OsString::from_vec(a.clone())).collect();
        prop_assert_eq!(parse_procargs2(&b).unwrap(), Argv::new(want));
    }

    /// Leading empty arguments right after the padding are arguments, and
    /// the environment after them stays unread.
    #[test]
    fn leading_empty_arguments_are_not_padding(
        path in no_nul(),
        empties in 1usize..10,
        rest in prop::collection::vec(no_nul(), 0..4),
        env in prop::collection::vec(prop::collection::vec(1u8..=255, 1..20), 1..4),
    ) {
        use std::os::unix::ffi::OsStringExt;
        let mut args = vec![Vec::new(); empties];
        args.extend(rest);
        let b = procargs(args.len(), &path, &args, &env);
        let want: Vec<OsString> = args.iter().map(|a| OsString::from_vec(a.clone())).collect();
        prop_assert_eq!(parse_procargs2(&b).unwrap(), Argv::new(want));
    }

    /// Whatever a command name holds (parentheses, spaces, any byte), the
    /// state is the letter after the `)` that closes it; arbitrary bytes
    /// never panic.
    #[test]
    fn the_state_survives_any_command_name(
        comm in prop::collection::vec(any::<u8>(), 0..32),
        state in prop::sample::select(b"RSDZTtXxIWPK".to_vec()),
        junk in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut stat = b"7 (".to_vec();
        stat.extend_from_slice(&comm);
        stat.extend_from_slice(b") ");
        stat.push(state);
        stat.extend_from_slice(b" 1 7 7 0 -1");
        prop_assert_eq!(parse_stat_state(&stat), Some(state));
        let _ = parse_stat_state(&junk);
    }

    /// A buffer cut before its last argument's NUL is refused: it never
    /// looks complete.
    #[test]
    fn truncated_procargs2_is_refused(
        args in prop::collection::vec(prop::collection::vec(1u8..=255, 1..20), 1..6),
        cut in 0usize..200,
    ) {
        let b = procargs(args.len(), b"/bin/x", &args, &[]);
        let cut = cut.min(b.len() - 1);
        prop_assert!(parse_procargs2(&b[..cut]).is_none());
    }
}
