//! Gates 25 and 26 (SPEC §15.2) with real processes: the evidence the
//! daemon gathers about a caller connected to a Unix socket.
//!
//! - Gate 25, evidence forgery: the test fixture agent (`fixture-agent`,
//!   which the builtin catalog knows by its file name) run under `env -i`
//!   is still an agent by ancestry; a grant for the terminal it runs in
//!   does not cover it; `CLAUDECODE=1` in a terminal only tightens.
//! - Gate 26, ancestry escape: a process under the fixture agent escapes by
//!   double fork, `setsid`, `nohup` with `disown`, `launchctl submit`
//!   (macOS) or `systemd-run --user` (Linux). Before the escape the same
//!   probe is an agent subject rooted at the fixture agent; after it, it is
//!   not covered by that root and is labeled "unknown".
//!
//! The caller is `ec-probe` (envcloak-testkit), which connects as the CLI
//! does and, on Linux, makes itself non-dumpable first, as the CLI does,
//! so its own executable is hidden from the test. Each scenario runs in a
//! session of its own (`ec-probe --session`), or on a pseudo-terminal of
//! its own, so its session leader is known.
//!
//! Local runs may happen under a real agent (a developer's Claude Code):
//! then a terminal opened by the test is inside that agent's tree, and is
//! rightly an agent subject rooted at it. The terminal checks read which
//! case applies from this test process's own evidence.
//!
//! `launchctl submit` and `systemd-run --user` change the user's service
//! manager, so they run only when `ENVCLOAK_TEST_SERVICE_MANAGER=1` (CI
//! sets it on both systems), with labels of their own that are removed
//! afterwards.
#![allow(clippy::unwrap_used)]

use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use envcloak_policy::{
    AgentCatalog, CatalogSource, Claims, ProcessInstance, SubjectEvidence, SubjectKind, gather,
};
use envcloak_testkit::{TestHome, testkit_bin};

fn probe() -> PathBuf {
    testkit_bin("ec-probe")
}

fn fixture() -> PathBuf {
    testkit_bin("fixture-agent")
}

/// The absolute path of `python3`, found on this process's `PATH`.
fn python3() -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join("python3"))
        .find(|p| p.is_file())
        .expect("python3 is needed on PATH")
}

/// A listening socket in a short temporary directory.
struct Listener {
    home: TestHome,
    sock: PathBuf,
    l: UnixListener,
}

impl Listener {
    fn new() -> Self {
        let home = TestHome::new();
        let sock = home.root().join("e.sock");
        let l = UnixListener::bind(&sock).unwrap();
        l.set_nonblocking(true).unwrap();
        Listener { home, sock, l }
    }

    /// The next connection, within 30 seconds.
    fn accept(&self) -> UnixStream {
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            match self.l.accept() {
                Ok((s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    return s;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < end, "no caller connected within 30 s");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("accept: {e}"),
            }
        }
    }

    /// The evidence for the next caller, gathered while it is connected,
    /// with no claims and with `claims`. The connection is then closed,
    /// which lets the caller exit.
    fn next_with(&self, claims: &[&str]) -> (SubjectEvidence, SubjectEvidence) {
        let s = self.accept();
        let peer = envcloak_sys::peer_identity(s.as_fd()).unwrap();
        let cat = AgentCatalog::builtin();
        let plain = gather(&peer, Claims::none(), &cat).unwrap();
        let claimed = gather(&peer, Claims::from_markers(claims).unwrap(), &cat).unwrap();
        (plain, claimed)
    }

    fn next(&self) -> SubjectEvidence {
        self.next_with(&[]).0
    }
}

/// A scenario process tree, ended when its stdin closes; killed on drop.
struct Scenario {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl Scenario {
    fn start(home: &TestHome, program: &Path, args: &[&std::ffi::OsStr]) -> Self {
        let mut cmd = Command::new(program);
        home.apply(&mut cmd);
        let mut child = cmd
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        Scenario { child, stdin }
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).unwrap()
    }

    /// Closes stdin and waits up to 30 seconds for the tree to end.
    fn finish(mut self) {
        drop(self.stdin.take());
        let end = Instant::now() + Duration::from_secs(30);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < end, "the scenario did not end");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Scenario {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `sh -c <script> sh <args...>` under `fixture-agent`, in a new session
/// led by `ec-probe --session`.
fn under_agent(l: &Listener, script: &str, extra: &[&str]) -> Scenario {
    let (p, f) = (probe(), fixture());
    let mut args: Vec<&std::ffi::OsStr> = vec![
        "--session".as_ref(),
        "--".as_ref(),
        f.as_os_str(),
        "sh".as_ref(),
        "-c".as_ref(),
        script.as_ref(),
        "sh".as_ref(),
        p.as_os_str(),
        l.sock.as_os_str(),
    ];
    args.extend(extra.iter().map(std::ffi::OsStr::new));
    Scenario::start(&l.home, &p, &args)
}

/// Runs argv[1:] as the leader of a new session whose controlling
/// terminal is a new pseudo-terminal, reading and dropping what it
/// prints; when this driver's stdin closes, kills that session's process
/// group.
const PTY: &str = r#"import os, pty, select, signal, sys
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], sys.argv[1:])
while True:
    r, _, _ = select.select([fd, 0], [], [])
    if fd in r:
        try:
            data = os.read(fd, 4096)
        except OSError:
            data = b''
        if not data:
            break
    if 0 in r and not os.read(0, 4096):
        break
try:
    os.killpg(pid, signal.SIGKILL)
except OSError:
    pass
os.waitpid(pid, 0)
"#;

/// `sh -c <script> sh <probe> <socket> <fixture-agent>` as the leader of a
/// session on a new pseudo-terminal.
fn on_terminal(l: &Listener, script: &str) -> Scenario {
    let (p, f) = (probe(), fixture());
    let args: Vec<&std::ffi::OsStr> = vec![
        "-c".as_ref(),
        PTY.as_ref(),
        "/bin/sh".as_ref(),
        "-c".as_ref(),
        script.as_ref(),
        "sh".as_ref(),
        p.as_os_str(),
        l.sock.as_os_str(),
        f.as_os_str(),
    ];
    Scenario::start(&l.home, &python3(), &args)
}

fn file_name(i: &ProcessInstance) -> String {
    i.exe
        .as_ref()
        .and_then(|e| e.path.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The root of this test process's own evidence when a known agent runs
/// it (a developer's session), else `None` (CI).
fn outer_agent_root() -> Option<ProcessInstance> {
    let (a, _b) = UnixStream::pair().unwrap();
    let me = envcloak_sys::peer_identity(a.as_fd()).unwrap();
    let e = gather(&me, Claims::none(), &AgentCatalog::builtin()).unwrap();
    e.nearest_agent().map(|_| e.root())
}

fn assert_rooted_at_the_fixture(e: &SubjectEvidence, at: usize) {
    let (n, label) = e.nearest_agent().expect("the fixture agent is found");
    assert_eq!(n, at, "{e:?}");
    assert_eq!(label.id, "fixture");
    assert_eq!(label.source, CatalogSource::Builtin);
    assert_eq!(e.kind(), SubjectKind::Agent);
    assert_eq!(e.root_index(), at);
    assert_eq!(file_name(&e.root()), "fixture-agent");
    assert!(e.covered_by(&e.root(), SubjectKind::Agent));
    assert!(e.agent_involved());
}

/// Gate 25: under `env -i` no marker reaches the caller, and the fixture
/// agent is still found by ancestry.
#[test]
fn gate25_a_known_agent_under_env_i_is_classified_by_ancestry() {
    let l = Listener::new();
    let (p, f) = (probe(), fixture());
    let args: Vec<&std::ffi::OsStr> = vec![
        "--session".as_ref(),
        "--".as_ref(),
        "/usr/bin/env".as_ref(),
        "-i".as_ref(),
        f.as_os_str(),
        p.as_os_str(),
        l.sock.as_os_str(),
    ];
    let s = Scenario::start(&l.home, &p, &args);
    let e = l.next();
    assert_rooted_at_the_fixture(&e, 1);
    // `env` exec'd the fixture agent, whose parent leads the session.
    assert_eq!(e.session_leader().unwrap().pid, s.pid());
    assert!(e.claims().markers().is_empty());
    assert!(!e.terminal());
    // On Linux the caller hides its executable, as the CLI does.
    if cfg!(target_os = "linux") {
        assert!(e.caller().exe.is_none(), "{e:?}");
    }
    s.finish();
}

/// Gate 25: a grant for a terminal does not cover an agent started in it,
/// with or without markers, and `CLAUDECODE=1` in that terminal only
/// tightens. The last caller double-forks out of the terminal's tree: it
/// keeps the terminal, and is unknown.
#[test]
fn gate25_a_terminal_grant_does_not_cover_an_agent_in_that_terminal() {
    let outer = outer_agent_root();
    let l = Listener::new();
    let s = on_terminal(
        &l,
        r#""$1" "$2"
"$3" "$1" "$2"
env -i "$3" "$1" "$2"
sh -c '"$0" --orphan-of $$ "$1" </dev/null >/dev/null 2>&1 &' "$1" "$2"
read x
"#,
    );

    // The terminal's own caller, and the same caller claiming CLAUDECODE.
    let (human, claimed) = l.next_with(&["CLAUDECODE"]);
    assert!(human.terminal());
    let leader = human.session_leader().unwrap().clone();
    assert_eq!(human.chain()[1].instance, leader, "sh leads the session");
    match &outer {
        None => {
            assert_eq!(human.kind(), SubjectKind::Terminal);
            assert!(human.root().same(&leader));
            assert!(human.covered_by(&leader, SubjectKind::Terminal));
            assert!(!human.agent_involved());
            assert_eq!(claimed.kind(), SubjectKind::Agent);
        }
        Some(root) => {
            eprintln!("an agent runs this test: the terminal is inside its tree");
            assert_eq!(human.kind(), SubjectKind::Agent);
            assert!(human.root().same(root));
            assert!(!human.covered_by(&leader, SubjectKind::Terminal));
        }
    }
    // The claim changes neither the chain nor the root, and tightens.
    assert_eq!(claimed.chain(), human.chain());
    assert!(claimed.root().same(&human.root()));
    assert!(claimed.agent_involved());
    // Labeled by the claim, or by the agent running this test.
    let want = human.label().map_or("claude-code", |l| l.id.as_str());
    assert_eq!(claimed.label().unwrap().id, want);
    assert!(!claimed.covered_by(&leader, SubjectKind::Terminal));

    // The fixture agent started in the terminal.
    let agent = l.next();
    assert_rooted_at_the_fixture(&agent, 1);
    assert!(agent.session_leader().unwrap().same(&leader));
    assert!(agent.chain().iter().any(|a| a.instance.same(&leader)));
    assert!(!agent.covered_by(&leader, SubjectKind::Terminal));
    assert!(
        !agent.covered_by(&leader, SubjectKind::Agent),
        "the agent barrier"
    );
    let first_agent = agent.root();

    // Under env -i: still the fixture agent, another instance of it.
    let bare = l.next();
    assert_rooted_at_the_fixture(&bare, 1);
    assert!(!bare.covered_by(&leader, SubjectKind::Terminal));
    assert!(!bare.covered_by(&first_agent, SubjectKind::Agent));

    // Out of the terminal's tree: it keeps the terminal, but its ancestry
    // no longer reaches the session leader.
    let orphan = l.next();
    assert!(orphan.terminal(), "{orphan:?}");
    assert!(orphan.session_leader().is_none());
    assert_eq!(orphan.kind(), SubjectKind::Unknown);
    assert!(!orphan.chain().iter().any(|a| a.instance.same(&leader)));
    assert!(!orphan.covered_by(&leader, SubjectKind::Terminal));
    assert!(!orphan.covered_by(&leader, SubjectKind::Unknown));
    assert!(orphan.nearest_agent().is_none());
    s.finish();
}

/// The gate 26 check: `escape` runs under the fixture agent after the same
/// probe connected from inside its tree. `own_session`: whether the
/// escaped probe leads a session of its own (`Some(true)`), is in a
/// session whose leader its ancestry no longer reaches (`Some(false)`), or
/// either (`None`: `launchd` starts some jobs in its own session).
fn escape_case(escape: &str, extra: &[&str], own_session: Option<bool>) {
    let l = Listener::new();
    let script = format!("\"$1\" \"$2\"\n{escape}\nread x\n");
    let s = under_agent(&l, &script, extra);

    // Inside: probe <- sh <- fixture-agent <- the session leader.
    let inside = l.next();
    assert_rooted_at_the_fixture(&inside, 2);
    assert_eq!(inside.session_leader().unwrap().pid, s.pid());
    let root = inside.root();

    // Escaped.
    let out = l.next();
    assert_eq!(out.kind(), SubjectKind::Unknown, "{out:?}");
    assert!(out.nearest_agent().is_none(), "{out:?}");
    assert!(!out.chain().iter().any(|a| a.instance.same(&root)));
    assert!(!out.chain().iter().any(|a| a.instance.pid == s.pid()));
    for kind in [
        SubjectKind::Agent,
        SubjectKind::Unknown,
        SubjectKind::Terminal,
    ] {
        assert!(!out.covered_by(&root, kind));
        assert!(!out.covered_by(inside.session_leader().unwrap(), kind));
    }
    assert!(!out.root().same(&root));
    assert!(!out.terminal());
    match own_session {
        Some(true) => assert!(out.session_leader().unwrap().same(out.caller()), "{out:?}"),
        Some(false) => assert!(out.session_leader().is_none(), "{out:?}"),
        None => {}
    }
    s.finish();
}

#[test]
fn gate26_a_double_fork_escapes_the_grant() {
    escape_case(
        r#"sh -c '"$0" --orphan-of $$ "$1" </dev/null >/dev/null 2>&1 &' "$1" "$2""#,
        &[],
        Some(false),
    );
}

#[test]
fn gate26_setsid_escapes_the_grant() {
    escape_case(
        r#"sh -c '"$0" --setsid --orphan-of $$ "$1" </dev/null >/dev/null 2>&1 &' "$1" "$2""#,
        &[],
        Some(true),
    );
}

#[test]
fn gate26_nohup_and_disown_escape_the_grant() {
    escape_case(
        r#"bash -c 'nohup "$0" --orphan-of $$ "$1" </dev/null >/dev/null 2>&1 & disown; exit 0' "$1" "$2""#,
        &[],
        Some(false),
    );
}

fn service_manager_allowed() -> bool {
    if std::env::var_os("ENVCLOAK_TEST_SERVICE_MANAGER").is_none() {
        eprintln!("skipped: set ENVCLOAK_TEST_SERVICE_MANAGER=1 to submit a test job");
        return false;
    }
    true
}

#[cfg(target_os = "macos")]
#[test]
fn gate26_launchctl_submit_escapes_the_grant() {
    if !service_manager_allowed() {
        return;
    }
    struct Job(String);
    impl Drop for Job {
        fn drop(&mut self) {
            let _ = Command::new("launchctl").args(["remove", &self.0]).status();
        }
    }
    let job = Job(format!("ai.envcloak.test-escape-{}", std::process::id()));
    escape_case(r#"launchctl submit -l "$3" -- "$1" "$2""#, &[&job.0], None);
}

#[cfg(target_os = "linux")]
#[test]
fn gate26_systemd_run_user_escapes_the_grant() {
    if !service_manager_allowed() {
        return;
    }
    let runtime = std::env::var("ENVCLOAK_TEST_SERVICE_RUNTIME_DIR")
        .expect("ENVCLOAK_TEST_SERVICE_RUNTIME_DIR names the user manager's runtime directory");
    struct Unit(String, String);
    impl Drop for Unit {
        fn drop(&mut self) {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", &self.0])
                .env("XDG_RUNTIME_DIR", &self.1)
                .env(
                    "DBUS_SESSION_BUS_ADDRESS",
                    format!("unix:path={}/bus", self.1),
                )
                .status();
        }
    }
    let unit = Unit(
        format!("envcloak-test-escape-{}", std::process::id()),
        runtime.clone(),
    );
    escape_case(
        r#"XDG_RUNTIME_DIR="$3" DBUS_SESSION_BUS_ADDRESS="unix:path=$3/bus" systemd-run --user --quiet --collect --unit="$4" -- "$1" "$2""#,
        &[&runtime, &unit.0],
        Some(true),
    );
}

/// The caller the evidence tests use is what they think it is: a process
/// that reads nothing and waits for the other end.
#[test]
fn the_probe_waits_for_the_other_end() {
    let l = Listener::new();
    let s = Scenario::start(&l.home, &probe(), &[l.sock.as_os_str()]);
    let mut conn = l.accept();
    let peer = envcloak_sys::peer_identity(conn.as_fd()).unwrap();
    assert_eq!(peer.pid, s.pid());
    conn.shutdown(std::net::Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    conn.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    drop(conn);
    s.finish();
}
