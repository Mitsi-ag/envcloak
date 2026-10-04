//! Gates 25 and 26 (SPEC §15.2) with real processes: the evidence the
//! daemon gathers about a caller connected to a Unix socket.
//!
//! - Gate 25, evidence forgery: the test fixture agent (`fixture-agent`,
//!   which the builtin catalog knows by its file name) run under `env -i`
//!   is still an agent by ancestry; a grant for the terminal it runs in
//!   does not cover it; `CLAUDECODE=1` in a terminal only tightens. A
//!   command run under enough nested shells to put the agent past the
//!   walk's cut is still not a terminal subject, and its proofs are
//!   refused. Only an agent's executable roots a grant above the caller's
//!   session: a process that calls itself an agent by `argv[0]`, script
//!   or command name is an agent subject, rooted in the caller's session.
//!   kimi-cli's shape, a Python script that titles itself `Kimi Code` as
//!   setproctitle does, is Kimi before and after its title, on each
//!   system.
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
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use envcloak_policy::{
    AgentCatalog, CatalogSource, Claims, MatchBasis, ProcessInstance, ProofRefusal,
    SubjectEvidence, SubjectKind, gather,
};
use envcloak_sys::MAX_ANCESTRY;
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
        Self::start_as(home, program, None, args)
    }

    /// As [`Scenario::start`], with `argv[0]` set to `arg0` when given.
    fn start_as(
        home: &TestHome,
        program: &Path,
        arg0: Option<&str>,
        args: &[&std::ffi::OsStr],
    ) -> Self {
        let mut cmd = Command::new(program);
        if let Some(arg0) = arg0 {
            cmd.arg0(arg0);
        }
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
    assert_eq!(label.basis, MatchBasis::Executable);
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

/// Gate 25: the fixture agent runs its command under `n` nested shells,
/// the last of which runs the caller under `env -i`. Under 60 the agent is
/// found at depth 62; under 70 it is past the walk's cut, and the caller
/// is still no terminal subject and may give no proof.
#[test]
fn gate25_an_agent_past_the_cut_still_counts() {
    let l = Listener::new();
    let s = under_agent(
        &l,
        r#"N='n=$1; shift; if [ "$n" -gt 0 ]; then sh -c "$0" "$0" $((n - 1)) "$@"; :; else exec /usr/bin/env -i "$@"; fi'
sh -c "$N" "$N" "$3" "$1" "$2"
sh -c "$N" "$N" "$4" "$1" "$2"
read x
"#,
        &["60", "70"],
    );
    // probe <- 60 shells <- sh <- fixture-agent <- the session leader.
    let within = l.next();
    assert_eq!(within.chain().len(), MAX_ANCESTRY);
    assert_rooted_at_the_fixture(&within, 62);
    assert_eq!(within.session_leader().unwrap().pid, s.pid());
    assert!(within.claims().markers().is_empty());

    // probe <- 70 shells: the fixture agent is not in the chain.
    let past = l.next();
    assert!(past.cut(), "{past:?}");
    assert_eq!(past.chain().len(), MAX_ANCESTRY);
    assert!(
        !past
            .chain()
            .iter()
            .any(|a| file_name(&a.instance) == "fixture-agent")
    );
    assert!(past.nearest_agent().is_none());
    assert!(past.claims().markers().is_empty());
    assert_eq!(past.kind(), SubjectKind::Unknown);
    assert!(past.agent_involved(), "its proofs are refused");
    for a in past.chain() {
        assert!(!past.covered_by(&a.instance, SubjectKind::Terminal));
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
    // It could prompt on that terminal: its proofs are refused.
    assert!(orphan.orphaned());
    assert!(orphan.agent_involved());
    s.finish();
}

/// Runs a script under `node`, as the older npm build of Claude Code runs:
/// it runs `/bin/sh` and the arguments after it, and exits with its status.
const NODE_RUNNER: &str = r#"const a = process.argv.slice(process.argv.indexOf("/bin/sh"));
const r = require("child_process").spawnSync(a[0], a.slice(1), { stdio: "inherit" });
process.exit(r.status === null ? 1 : r.status);
"#;

/// The absolute path of `node`, found on this process's `PATH`. In CI it
/// must be there; elsewhere a test that needs it is skipped without it.
fn node() -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let found = std::env::split_paths(&path)
        .map(|d| d.join("node"))
        .find(|p| p.is_file());
    if found.is_none() {
        assert!(
            std::env::var_os("CI").is_none(),
            "node is needed on PATH in CI"
        );
        eprintln!("skipped: no node on PATH");
    }
    found
}

/// Two callers under one holder process, each leading a session of its
/// own, as Claude Code and Codex run their commands: the holder runs
/// `/bin/sh -c <script> sh <probe> <socket>` (`program`, with `argv[0]`
/// set to `arg0` when given, and `before` in front of `/bin/sh`), and the
/// script runs the two callers one after the other. Returns their
/// evidence, the holder, and the scenario, still running.
fn two_sessions_under(
    l: &Listener,
    program: &Path,
    arg0: Option<&str>,
    before: &[&std::ffi::OsStr],
) -> (SubjectEvidence, SubjectEvidence, ProcessInstance, Scenario) {
    let p = probe();
    let sh: [&std::ffi::OsStr; 6] = [
        "/bin/sh".as_ref(),
        "-c".as_ref(),
        "\"$1\" --setsid \"$2\"\n\"$1\" --setsid \"$2\"\nread x\n".as_ref(),
        "sh".as_ref(),
        p.as_os_str(),
        l.sock.as_os_str(),
    ];
    let mut args: Vec<&std::ffi::OsStr> = before.to_vec();
    args.extend(sh);
    let s = Scenario::start_as(&l.home, program, arg0, &args);
    let first = l.next();
    let second = l.next();
    // Each: probe (its own session) <- sh <- the holder.
    let holder = first.chain()[2].instance.clone();
    for e in [&first, &second] {
        assert!(e.session_leader().unwrap().same(e.caller()), "{e:?}");
        assert!(e.chain()[2].instance.same(&holder), "{e:?}");
        assert!(!e.terminal());
    }
    (first, second, holder, s)
}

/// The holder is an agent by what it says about itself only: the callers
/// are agent subjects, but each is rooted in its own session, and neither
/// is covered by a grant rooted at the holder or at the other's root.
fn assert_rooted_in_its_session(
    first: &SubjectEvidence,
    second: &SubjectEvidence,
    holder: &ProcessInstance,
    id: &str,
) {
    for e in [first, second] {
        let (n, label) = e.nearest_agent().expect("the holder is labeled");
        assert_eq!(n, 2, "{e:?}");
        assert_eq!(
            (label.id.as_str(), label.source, label.basis),
            (id, CatalogSource::Builtin, MatchBasis::Asserted)
        );
        assert_eq!(e.kind(), SubjectKind::Agent);
        assert!(e.agent_involved());
        assert!(e.root().same(e.caller()), "{e:?}");
    }
    for kind in [
        SubjectKind::Agent,
        SubjectKind::Unknown,
        SubjectKind::Terminal,
    ] {
        assert!(!second.covered_by(&first.root(), kind), "{kind:?}");
        assert!(!second.covered_by(holder, kind), "{kind:?}");
        assert!(!first.covered_by(holder, kind), "{kind:?}");
    }
}

/// Gate 25 and review finding F-37: only an agent's executable roots a
/// grant above the caller's session. An agent runs each command in a
/// session of its own, so a grant for the fixture agent, known by its
/// executable, covers both of its commands. A process that only calls
/// itself an agent (by `argv[0]` or its script under `node`, or on Linux by
/// its command name, here from a link named `fixture-agent` to another
/// program) is an agent subject all the same, but its grants are rooted in
/// the caller's session, so a grant for one of its commands covers no
/// other.
#[test]
fn gate25_only_an_agents_executable_roots_a_grant_above_the_session() {
    let outer = outer_agent_root();
    let l = Listener::new();
    let f = fixture();
    // The fixture agent, by its executable.
    let (first, second, holder, s) = two_sessions_under(&l, &f, None, &[]);
    let (n, label) = first.nearest_agent().unwrap();
    assert_eq!(
        (n, label.id.as_str(), label.basis),
        (2, "fixture", MatchBasis::Executable)
    );
    assert!(first.root().same(&holder));
    assert!(second.root().same(&holder));
    assert!(second.covered_by(&first.root(), SubjectKind::Agent));
    assert!(!second.covered_by(&first.root(), SubjectKind::Terminal));
    s.finish();

    // Another program, run through a link named `fixture-agent`.
    let link = l.home.root().join("fixture-agent");
    std::os::unix::fs::symlink(probe(), &link).unwrap();
    let (first, second, holder, s) =
        two_sessions_under(&l, &link, None, &["--session".as_ref(), "--".as_ref()]);
    if cfg!(target_os = "linux") {
        // The command name is the link's; the executable is the program's.
        assert_rooted_in_its_session(&first, &second, &holder, "fixture");
    } else {
        // macOS names the process after the file it runs.
        assert!(first.chain()[2].agent.is_none(), "{first:?}");
        assert!(!first.root().same(&holder));
        if outer.is_none() {
            assert!(first.root().same(first.caller()));
            assert!(!second.covered_by(&first.root(), SubjectKind::Agent));
        }
    }
    s.finish();

    let Some(node) = node() else {
        return;
    };
    // `node` with argv[0] `fixture-agent` (as `process.title` sets it).
    let (first, second, holder, s) = two_sessions_under(
        &l,
        &node,
        Some("fixture-agent"),
        &["-e".as_ref(), NODE_RUNNER.as_ref(), "--".as_ref()],
    );
    assert_rooted_in_its_session(&first, &second, &holder, "fixture");
    s.finish();

    // `node` running a script at the path of Claude Code's npm build.
    let dir = l.home.root().join("n/@anthropic-ai/claude-code");
    std::fs::create_dir_all(&dir).unwrap();
    let cli = dir.join("cli.js");
    std::fs::write(&cli, NODE_RUNNER).unwrap();
    let (first, second, holder, s) =
        two_sessions_under(&l, &node, None, &[cli.as_os_str(), "--".as_ref()]);
    assert_rooted_in_its_session(&first, &second, &holder, "claude-code");
    s.finish();
}

/// Gates 23 and 25 with real processes (M2 plan risk K-03): the fixture
/// agent starts a command on a new pseudo-terminal of its own, in a new
/// session the command leads (the shape of Gemini CLI's `node-pty` and
/// Codex's `tty: true`), under `env -i`. The command has a controlling
/// terminal and leads its session, yet it is an agent subject rooted at
/// the fixture agent: a grant for its terminal does not cover it, and its
/// proofs are refused. The control: the same tree under a copy of the
/// fixture agent by another name, which the catalog does not know, is a
/// terminal subject a terminal grant covers and whose proofs are taken,
/// which is what the catalog prevents. Mutation checked: removing the
/// fixture agent's executable pattern fails this test.
#[test]
fn gate23_a_command_an_agent_starts_on_a_pty_of_its_own_is_an_agent() {
    let outer = outer_agent_root();
    let l = Listener::new();
    let run = |holder: &Path| {
        let (p, py) = (probe(), python3());
        let args: Vec<&std::ffi::OsStr> = vec![
            py.as_os_str(),
            "-c".as_ref(),
            PTY.as_ref(),
            "/usr/bin/env".as_ref(),
            "-i".as_ref(),
            p.as_os_str(),
            l.sock.as_os_str(),
        ];
        let s = Scenario::start(&l.home, holder, &args);
        (l.next(), s)
    };
    // probe (leading its session on the new terminal) <- python3 (the
    // pseudo-terminal's owner) <- fixture-agent.
    let (agent, s) = run(&fixture());
    assert!(agent.terminal(), "{agent:?}");
    assert!(agent.session_leader().unwrap().same(agent.caller()));
    assert!(agent.claims().markers().is_empty());
    assert_rooted_at_the_fixture(&agent, 2);
    assert!(!agent.covered_by(agent.caller(), SubjectKind::Terminal));
    assert!(!agent.covered_by(&agent.root(), SubjectKind::Terminal));
    assert_eq!(agent.proof_refusal(), Some(ProofRefusal::Agent));
    s.finish();

    let copy = l.home.root().join("not-an-agent");
    std::fs::copy(fixture(), &copy).unwrap();
    let (control, s) = run(&copy);
    assert!(control.terminal(), "{control:?}");
    assert!(control.session_leader().unwrap().same(control.caller()));
    match outer {
        None => {
            assert!(control.nearest_agent().is_none(), "{control:?}");
            assert_eq!(control.kind(), SubjectKind::Terminal);
            assert!(control.covered_by(control.caller(), SubjectKind::Terminal));
            assert_eq!(control.proof_refusal(), None);
        }
        Some(_) => eprintln!("an agent runs this test: the control is inside its tree"),
    }
    s.finish();
}

/// A Python program in the shape of kimi-cli's launcher (`kimi`, a script
/// whose shebang names the Python it runs under): it runs `ec-probe` under
/// `env -i` as its shell tool runs a command, then titles itself as
/// setproctitle does (kimi-cli's src/kimi_cli/utils/proctitle.py: the
/// title written over its arguments, and on Linux its command name set
/// with `prctl(PR_SET_NAME)`), and runs the probe again. An empty title
/// skips the second run.
const TITLED: &str = r#"
import ctypes, subprocess, sys
probe, sock, title = sys.argv[1], sys.argv[2], sys.argv[3]
subprocess.run(["/usr/bin/env", "-i", probe, sock], check=True)
if not title:
    sys.exit(0)
t = title.encode()
if sys.platform == "darwin":
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    libc._NSGetArgv.restype = ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))
    libc._NSGetArgc.restype = ctypes.POINTER(ctypes.c_int)
    libc.strlen.restype = ctypes.c_size_t
    libc.strlen.argtypes = [ctypes.c_void_p]
    argv = libc._NSGetArgv().contents
    argc = libc._NSGetArgc().contents.value
    start = argv[0]
    end = argv[argc - 1] + libc.strlen(argv[argc - 1]) + 1
else:
    libc = ctypes.CDLL(None)
    libc.prctl(15, ctypes.c_char_p(t[:15]), 0, 0, 0)
    stat = open("/proc/self/stat", "rb").read()
    f = stat[stat.rindex(b")") + 2:].split()
    start, end = int(f[45]), int(f[46])
n = end - start
ctypes.memmove(start, t + b"\0" * (n - len(t)), n)
subprocess.run(["/usr/bin/env", "-i", probe, sock], check=True)
"#;

/// kimi-cli (task M2-10: Kimi, Kimi Code and kimi-cli by one entry) is a
/// Python program: its `kimi` and `kimi-cli` scripts run under Python,
/// which the catalog knows as an interpreter, and once it titles itself
/// `Kimi Code` its arguments and (on Linux) its command name say so.
/// Real processes on each system, the program's own commands as the
/// callers: before the title (by its script, and on Linux by the command
/// name the script gives it) and after it (by its title), Python is Kimi,
/// asserted, so its commands are agent subjects whose proofs are refused
/// and whose grants are rooted no higher than their session. The controls,
/// the same program as `tool` and titled `Kimi Coder`, are not Kimi.
/// Mutation checked: removing the Python interpreters fails the macOS
/// cases and the scripts, and removing `Kimi Code` from the names fails the
/// titled ones.
#[test]
fn kimi_cli_under_python_is_kimi_before_and_after_its_title() {
    let l = Listener::new();
    let bin = l.home.home().join(".local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let py = python3();
    let body = format!("#!{}\n{TITLED}", py.display());
    let script = |name: &str| {
        let path = bin.join(name);
        std::fs::write(&path, &body).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        path
    };
    let kimi_at_1 = |e: &SubjectEvidence, what: &str| {
        let a = &e.chain()[1];
        let label = a.agent.as_ref().unwrap_or_else(|| panic!("{what}: {e:?}"));
        println!(
            "measurement: catalog kimi-cli shape os={}: {what}: {} ({:?}), executable {:?}",
            std::env::consts::OS,
            label.id,
            label.basis,
            file_name(&a.instance)
        );
        assert_eq!(
            (label.id.as_str(), label.basis),
            ("kimi", MatchBasis::Asserted),
            "{what}"
        );
        assert!(!label.may_root_above_session());
        assert_eq!(e.kind(), SubjectKind::Agent, "{what}");
        assert_eq!(e.proof_refusal(), Some(ProofRefusal::Agent), "{what}");
        assert!(e.root_index() <= 2, "{what}: rooted in its session: {e:?}");
    };
    for name in ["kimi", "kimi-cli"] {
        let path = script(name);
        let (p, sock) = (probe(), l.sock.clone());
        let args: Vec<&std::ffi::OsStr> = vec![
            "--session".as_ref(),
            "--".as_ref(),
            path.as_os_str(),
            p.as_os_str(),
            sock.as_os_str(),
            "Kimi Code".as_ref(),
        ];
        let s = Scenario::start(&l.home, &p, &args);
        kimi_at_1(&l.next(), &format!("{name}, before its title"));
        kimi_at_1(&l.next(), &format!("{name}, titled Kimi Code"));
        s.finish();
    }
    // The controls: another name, another title.
    let path = script("tool");
    let (p, sock) = (probe(), l.sock.clone());
    let args: Vec<&std::ffi::OsStr> = vec![
        "--session".as_ref(),
        "--".as_ref(),
        path.as_os_str(),
        p.as_os_str(),
        sock.as_os_str(),
        "Kimi Coder".as_ref(),
    ];
    let s = Scenario::start(&l.home, &p, &args);
    for what in ["tool", "tool titled Kimi Coder"] {
        let e = l.next();
        assert!(e.chain()[1].agent.is_none(), "{what}: {e:?}");
    }
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
    // No proof from it either (SPEC §10b): an orphan's ancestry is lost,
    // and a process that leads a session of its own, or runs in pid 1's,
    // has no terminal a person could type into. So a passphrase an agent
    // captured does not work from an escape.
    assert!(out.proof_refusal().is_some(), "{out:?}");
    match own_session {
        Some(true) => {
            assert!(out.session_leader().unwrap().same(out.caller()), "{out:?}");
            assert!(!out.orphaned());
            assert_eq!(out.proof_refusal(), Some(ProofRefusal::NoTerminal));
        }
        Some(false) => {
            assert!(out.session_leader().is_none(), "{out:?}");
            // An orphan: its proofs are refused, as they were inside.
            assert!(out.orphaned(), "{out:?}");
            assert!(out.agent_involved(), "{out:?}");
        }
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

/// Whether the service-manager escapes may run. CI must run them (it sets
/// the variable on both systems), so a missing variable there fails
/// rather than skipping a gate case unseen: libtest hides what a passing
/// test prints.
fn service_manager_allowed() -> bool {
    if std::env::var_os("ENVCLOAK_TEST_SERVICE_MANAGER").is_none() {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI must set ENVCLOAK_TEST_SERVICE_MANAGER=1: gate 26 needs the service-manager escape"
        );
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
