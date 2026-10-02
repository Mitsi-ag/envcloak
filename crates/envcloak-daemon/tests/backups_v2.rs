//! File backups v2 over the daemon's socket (M2 plan D-07, task M2-05;
//! docs/IPC.md "Backups v2"; the backup halves of gates 37 and 39, gate
//! 33's restore order):
//! - only paths under the allowed roots are taken, the caps refuse, and
//!   no field says who made a backup: a forged one is `invalid_params`;
//! - a backup comes back byte for byte, a 200 MiB file with one proof and
//!   one audit entry while the daemon's memory stays bounded, and
//!   `backups/` and the temporary directories hold no plaintext;
//! - only the process instance that began a backup may add to it, commit
//!   it and record its results, even against another process in the same
//!   agent root; a committed backup is frozen and a result recorded once;
//!   a creator that exits first leaves `result_unrecorded`;
//! - restore takes a proof from a terminal subject only, names an agent
//!   creator on its statement and needs `--created-by-agent` for it;
//! - a lease serves only its own process, ends at lock and when its
//!   process exits; an audit entry that cannot be written issues no lease,
//!   and a lease's entry is on disk before its first chunk; a backup that
//!   does not open whole releases nothing;
//! - a killed client or daemon leaves no listed partial backup.
//!
//! The caller is this test process, made a terminal session first. Other
//! processes are this test binary run again as a child
//! ([`backup_v2_child`]): a worker that answers JSON commands on its
//! standard input, run directly (another process on this terminal), under
//! `fixture-agent` in a session of its own on a pseudo-terminal of its own
//! (an agent in another terminal window), or as two workers under one
//! `fixture-agent` (two processes of one agent root). Under a developer's
//! agent the proofs are refused, as they must be: run the tests outside
//! its tree.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use common::{client, data_dir, passphrase, seed_vault};
use envcloak_core::SecretBytes;
use envcloak_core::audit::AuditKind;
use envcloak_core::file_backup_v2::{CHUNK_V2, chunk_len, chunks_of};
use envcloak_core::vault::{LockedVault, VaultPaths};
use envcloak_ipc::proto::{BackupBeginParams, BackupPlanFile, ErrorKind};
use envcloak_ipc::view::{BackupListView, BackupStateView, RestoreLeaseView, VaultState};
use envcloak_ipc::{Client, ClientError, RunPaths};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, canaries, fresh_seed, testkit_bin,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The marker the fixture catalog knows as an agent's.
const AGENT: &str = "ENVCLOAK_FIXTURE_AGENT";
/// The fixture agent's display name.
const AGENT_NAME: &str = "EnvCloak test fixture agent";
const MIB: u64 = 1 << 20;

fn rpc(e: ClientError) -> (ErrorKind, Option<&'static str>) {
    match e {
        ClientError::Rpc(r) => (r.kind, r.reason),
        other => panic!("expected an error response, got {other:?}"),
    }
}

/// The bytes at `[at, at + len)` of a file of `salt`: filler that is not
/// UTF-8, with a fixture of `cs` at every 1,000,003rd byte, one of them
/// across the first chunk boundary.
fn bytes_at(cs: &[Canary], salt: u8, at: u64, len: usize) -> Vec<u8> {
    // The filler repeats every 251 bytes: one period, then copies of it.
    let period: Vec<u8> = (0..251u64)
        .map(|i| (((at + i) * 31 + u64::from(salt)) % 251) as u8 | 0x80)
        .collect();
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let n = (len - out.len()).min(period.len());
        out.extend_from_slice(&period[..n]);
    }
    let mut place = |start: u64, v: &[u8]| {
        let end = start + v.len() as u64;
        let (lo, hi) = (start.max(at), end.min(at + len as u64));
        if lo < hi {
            out[(lo - at) as usize..(hi - at) as usize]
                .copy_from_slice(&v[(lo - start) as usize..(hi - start) as usize]);
        }
    };
    let step = 1_000_003u64;
    let first = at / step;
    for k in first..=(at + len as u64) / step {
        place(k * step, cs[(k as usize) % cs.len()].value());
    }
    place(CHUNK_V2 as u64 - 9, cs[0].value());
    out
}

/// Chunk `chunk` of a file of `size` bytes and `salt`.
fn chunk_of(cs: &[Canary], size: u64, salt: u8, chunk: u64) -> Vec<u8> {
    let at = chunk * CHUNK_V2 as u64;
    bytes_at(cs, salt, at, chunk_len(size, chunk).unwrap())
}

/// The SHA-256 of a whole file of `size` bytes and `salt`.
fn sha_of(cs: &[Canary], size: u64, salt: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    for c in 0..chunks_of(size) {
        h.update(chunk_of(cs, size, salt, c));
    }
    h.finalize().into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A file a backup holds: where, how big, and its bytes' salt, or fixed
/// text.
#[derive(Debug, Clone)]
struct Spec {
    path: String,
    size: u64,
    salt: u8,
    text: Option<Vec<u8>>,
}

impl Spec {
    fn made(path: &Path, size: u64, salt: u8) -> Spec {
        Spec {
            path: path.to_str().unwrap().to_owned(),
            size,
            salt,
            text: None,
        }
    }

    fn chunk(&self, cs: &[Canary], c: u64) -> Vec<u8> {
        match &self.text {
            Some(t) => {
                let start = c as usize * CHUNK_V2;
                t[start..start + chunk_len(self.size, c).unwrap()].to_vec()
            }
            None => chunk_of(cs, self.size, self.salt, c),
        }
    }

    fn sha(&self, cs: &[Canary]) -> [u8; 32] {
        match &self.text {
            Some(t) => Sha256::digest(t).into(),
            None => sha_of(cs, self.size, self.salt),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "size": self.size,
            "salt": self.salt,
            "text": self.text.as_ref().map(|t| String::from_utf8(t.clone()).unwrap()),
        })
    }

    fn from_json(v: &Value) -> Spec {
        Spec {
            path: v["path"].as_str().unwrap().to_owned(),
            size: v["size"].as_u64().unwrap(),
            salt: u8::try_from(v["salt"].as_u64().unwrap()).unwrap(),
            text: v["text"].as_str().map(|t| t.as_bytes().to_vec()),
        }
    }
}

fn begin_params(purpose: &str, files: &[Spec], claims: &[&str]) -> BackupBeginParams {
    BackupBeginParams {
        purpose: purpose.to_owned(),
        files: files
            .iter()
            .map(|f| BackupPlanFile {
                path: f.path.clone(),
                size: f.size,
                mode: 0o600,
            })
            .collect(),
        claims: claims.iter().map(|c| (*c).to_owned()).collect(),
    }
}

/// Chunks sent or read on one connection before the next is opened: the
/// backup and its lease work across connections.
const PER_CONNECTION: u64 = 16;

/// Puts every chunk of `files` into backup `id`, on a fresh connection
/// for each file and every [`PER_CONNECTION`] chunks.
fn put_all(paths: &RunPaths, cs: &[Canary], id: &str, files: &[Spec]) -> Result<(), ClientError> {
    for (i, f) in files.iter().enumerate() {
        let n = chunks_of(f.size);
        let mut conn = Client::connect(paths)?;
        for c in 0..n {
            if c > 0 && c % PER_CONNECTION == 0 {
                conn = Client::connect(paths)?;
            }
            let data = SecretBytes::from_vec(f.chunk(cs, c));
            let put = conn.backup_v2_put(
                id,
                u32::try_from(i).unwrap(),
                u32::try_from(c).unwrap(),
                data,
            )?;
            assert_eq!(put.last, c + 1 == n);
        }
    }
    Ok(())
}

/// Reads every chunk of every file under `lease` and compares each with
/// the bytes it backed up; the first chunk's file view and the
/// statement's SHA-256 too.
fn read_back(paths: &RunPaths, cs: &[Canary], lease: &RestoreLeaseView, files: &[Spec]) {
    assert_eq!(lease.statement.files.len(), files.len());
    for (i, f) in files.iter().enumerate() {
        let want = hex(&f.sha(cs));
        assert_eq!(lease.statement.files[i].sha256, want);
        assert_eq!(lease.statement.files[i].path, f.path);
        let n = chunks_of(f.size);
        let mut conn = Client::connect(paths).unwrap();
        for c in 0..n {
            if c > 0 && c % PER_CONNECTION == 0 {
                conn = Client::connect(paths).unwrap();
            }
            let got = conn
                .backup_v2_read(
                    &lease.lease,
                    u32::try_from(i).unwrap(),
                    u32::try_from(c).unwrap(),
                )
                .unwrap();
            assert_eq!(got.last, c + 1 == n);
            assert!(
                got.data.as_secret().ct_eq(&f.chunk(cs, c)),
                "file {i} chunk {c}"
            );
            if c == 0 {
                let view = got.file.unwrap();
                assert_eq!(
                    (view.path.as_str(), view.sha256.as_str()),
                    (f.path.as_str(), want.as_str())
                );
            } else {
                assert!(got.file.is_none());
            }
        }
    }
}

/// A seeded vault, unlocked, behind a daemon with its test trace.
struct Fixture {
    cs: Vec<Canary>,
    seed: u64,
    home: TestHome,
    d: Daemon,
    /// The file that lets the daemon go on from its pause point.
    release: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        Self::pausing(None)
    }

    /// A fixture whose daemon stops at the pause point `site`, when given,
    /// until [`Fixture::release`] (`envcloak_sys::pause_point`).
    fn pausing(site: Option<&str>) -> Self {
        common::terminal_session();
        let seed = fresh_seed();
        let cs = canaries(seed);
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);
        let release = home.home().join("pause-released");
        let mut cmd = Command::new(common::exe());
        home.apply(&mut cmd).env(envcloak_sys::testing::TRACE, "1");
        if let Some(site) = site {
            cmd.env(envcloak_sys::testing::PAUSE_SITE, site)
                .env(envcloak_sys::testing::PAUSE_RELEASE, &release);
        }
        let d = Daemon::start_command(cmd, &[]);
        client(&home).unlock(passphrase(&cs), &[]).unwrap();
        Fixture {
            cs,
            seed,
            home,
            d,
            release,
        }
    }

    /// Waits until the daemon stops at its pause point `site`.
    fn wait_paused(&mut self, site: &str) {
        let line = format!("envcloak test: paused at {site}");
        assert!(
            self.d.wait_for_log(&line, Duration::from_secs(30)),
            "the daemon never stopped at {site}"
        );
    }

    /// Lets the daemon go on from its pause point.
    fn release(&self) {
        std::fs::write(&self.release, b"").unwrap();
    }

    fn daemon(home: &TestHome) -> Daemon {
        let mut cmd = Command::new(common::exe());
        home.apply(&mut cmd).env(envcloak_sys::testing::TRACE, "1");
        Daemon::start_command(cmd, &[])
    }

    /// The fixtures a file's bytes hold: the story's canaries, not the
    /// kit.
    fn files_cs(&self) -> &[Canary] {
        &self.cs[..self.cs.len() - 1]
    }

    fn paths(&self) -> RunPaths {
        common::run_paths(&self.home)
    }

    /// The passphrase as text, for a child to send.
    fn pass(&self) -> String {
        envcloak_testkit::by_label(&self.cs, envcloak_testkit::labels::VAULT_PASSPHRASE)
            .as_str()
            .to_owned()
    }

    fn claude(&self, rel: &str) -> PathBuf {
        self.home.home().join(".claude").join(rel)
    }

    fn list(&self) -> BackupListView {
        client(&self.home).backup_v2_list().unwrap()
    }

    /// Backs `files` up as this process, a terminal subject.
    fn backup(&self, purpose: &str, files: &[Spec]) -> String {
        let id = client(&self.home)
            .backup_v2_begin(&begin_params(purpose, files, &[]))
            .unwrap()
            .id;
        put_all(&self.paths(), self.files_cs(), &id, files).unwrap();
        client(&self.home).backup_v2_commit(&id).unwrap();
        id
    }

    fn open(
        &self,
        id: &str,
        tick: bool,
        unrecorded: bool,
    ) -> Result<RestoreLeaseView, ClientError> {
        client(&self.home).backup_v2_open_restore(id, passphrase(&self.cs), tick, unrecorded, &[])
    }

    /// Stops the daemon and starts it again, unlocked: nothing it held in
    /// memory survives.
    fn restart(&mut self) {
        self.d.signal("-TERM");
        assert!(self.d.wait_exit(Duration::from_secs(30)).is_some());
        self.d = Self::daemon(&self.home);
        client(&self.home)
            .unlock(passphrase(&self.cs), &[])
            .unwrap();
    }

    /// The audit log's entries, read after the daemon stopped.
    fn audit_after_stop(&mut self) -> Vec<envcloak_core::audit::AuditEntry> {
        self.d.signal("-TERM");
        assert!(self.d.wait_exit(Duration::from_secs(30)).is_some());
        self.read_audit()
    }

    fn read_audit(&self) -> Vec<envcloak_core::audit::AuditEntry> {
        let v = LockedVault::open(&VaultPaths::under(data_dir(&self.home)))
            .unwrap()
            .unlock_with_passphrase(&passphrase(&self.cs))
            .map_err(|(_, e)| e)
            .unwrap();
        let (entries, _) = v.read_audit().unwrap();
        for e in &entries {
            assert_no_canary(format!("{:?}", e.record).as_bytes(), &self.cs);
        }
        entries
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }

    /// Runs this binary as a child in `mode`, wrapped by `wrap` when given
    /// (`host`: a session of its own on a pseudo-terminal, then
    /// `fixture-agent`).
    fn child(&self, mode: &str, host: bool) -> Worker {
        self.spawn(if host { "host" } else { mode }, mode)
    }

    /// Runs this binary as a worker under `fixture-agent` on this
    /// terminal, in this session: an agent the person runs here.
    fn agent_here(&self) -> Worker {
        self.spawn("here", "worker")
    }

    fn spawn(&self, outer: &str, mode: &str) -> Worker {
        let exe = std::env::current_exe().unwrap();
        let mut cmd = Command::new(&exe);
        self.home
            .apply(&mut cmd)
            .args([
                "--exact",
                "backup_v2_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_MODE, outer)
            .env(CHILD_INNER, mode)
            .env(CHILD_RUN, envcloak_testkit::daemon_run_dir(&self.home))
            .env(CHILD_SEED, self.seed.to_string())
            .env(CHILD_AGENT_BIN, testkit_bin("fixture-agent"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let ready = read_reply(&mut out);
        assert_eq!(ready["ready"], true, "{ready}");
        Worker { child, stdin, out }
    }
}

/// A child of this test binary answering JSON commands.
struct Worker {
    child: Child,
    stdin: ChildStdin,
    out: BufReader<ChildStdout>,
}

impl Worker {
    fn ask(&mut self, cmd: Value) -> Value {
        writeln!(self.stdin, "{cmd}").unwrap();
        self.stdin.flush().unwrap();
        read_reply(&mut self.out)
    }

    /// Ends the child and waits for it.
    fn end(mut self) {
        let _ = writeln!(self.stdin, "{}", json!({"op": "exit"}));
        drop(self.stdin);
        self.child.wait().unwrap();
    }
}

/// The JSON after the next `@@ ` a child prints (the test harness may
/// have put the test's name before it on the line).
fn read_reply(out: &mut BufReader<ChildStdout>) -> Value {
    let mut line = String::new();
    loop {
        line.clear();
        assert!(out.read_line(&mut line).unwrap() > 0, "the child ended");
        if let Some(at) = line.find("@@ ") {
            return serde_json::from_str(&line[at + 3..]).unwrap();
        }
    }
}

/// An error reply's kind token.
fn err(v: &Value) -> &str {
    v["err"]
        .as_str()
        .unwrap_or_else(|| panic!("expected an error, got {v}"))
}

const CHILD_MODE: &str = "ENVCLOAK_TEST_BACKUP_CHILD";
const CHILD_INNER: &str = "ENVCLOAK_TEST_BACKUP_INNER";
const CHILD_RUN: &str = "ENVCLOAK_TEST_BACKUP_RUN";
const CHILD_SEED: &str = "ENVCLOAK_TEST_BACKUP_SEED";
const CHILD_AGENT_BIN: &str = "ENVCLOAK_TEST_BACKUP_AGENT_BIN";
const CHILD_HELD: &str = "ENVCLOAK_TEST_BACKUP_HELD";
const CHILD_MAKER: &str = "ENVCLOAK_TEST_BACKUP_MAKER";

fn reply(v: &Value) {
    println!("@@ {v}");
    std::io::stdout().flush().unwrap();
}

fn err_json(e: ClientError) -> Value {
    match e {
        ClientError::Rpc(r) => json!({"err": r.kind.token(), "reason": r.reason}),
        other => json!({"err": format!("{other:?}")}),
    }
}

/// Runs only as a child of a test here. `worker` answers one JSON command
/// per line (`begin`, `put_next`, `put`, `commit`, `result`, `list`,
/// `open`, `read`, `exit`) with one `@@ `-prefixed JSON line; `notty`
/// first leaves its session for one without a terminal, then works the
/// same way; `pair` runs two workers and passes each command to the one
/// its `to` names; `host` makes a session of its own on a pseudo-terminal
/// and runs `fixture-agent` with this binary in the inner mode, and
/// `here` does so in its parent's session, on its terminal.
#[test]
fn backup_v2_child() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    match mode.as_str() {
        "host" | "here" => {
            if mode == "host" {
                envcloak_sys::testing::enter_terminal_session().unwrap();
            }
            let exe = std::env::current_exe().unwrap();
            let status = Command::new(std::env::var_os(CHILD_AGENT_BIN).unwrap())
                .arg("--")
                .arg(exe)
                .args([
                    "--exact",
                    "backup_v2_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_MODE, std::env::var(CHILD_INNER).unwrap())
                .status()
                .unwrap();
            std::process::exit(status.code().unwrap_or(1));
        }
        "pair" => {
            let spawn = || {
                let mut c = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "backup_v2_child",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD_MODE, "worker")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap();
                let stdin = c.stdin.take().unwrap();
                let mut out = BufReader::new(c.stdout.take().unwrap());
                assert_eq!(read_reply(&mut out)["ready"], true);
                Worker {
                    child: c,
                    stdin,
                    out,
                }
            };
            let mut a = spawn();
            let mut b = spawn();
            reply(&json!({"ready": true}));
            for line in std::io::stdin().lock().lines() {
                let cmd: Value = serde_json::from_str(&line.unwrap()).unwrap();
                if cmd["op"] == "exit" {
                    break;
                }
                let w = if cmd["to"] == "A" { &mut a } else { &mut b };
                reply(&w.ask(cmd));
            }
            a.end();
            b.end();
        }
        "worker" | "notty" => {
            if mode == "notty" {
                envcloak_sys::testing::setsid().unwrap();
            }
            worker();
        }
        "holder" => holder(),
        other => panic!("unknown child mode {other}"),
    }
}

/// A process holding a connection another process made (its standard
/// input), which it uses only once that process has exited: it records
/// a result for file 0 of the backup [`CHILD_HELD`] names, and says what
/// came back, or that the daemon closed the connection.
fn holder() {
    use std::os::fd::AsFd;
    let maker: u32 = std::env::var(CHILD_MAKER).unwrap().parse().unwrap();
    let mut conn = std::os::unix::net::UnixStream::from(
        std::io::stdin().as_fd().try_clone_to_owned().unwrap(),
    );
    conn.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let end = Instant::now() + Duration::from_secs(30);
    while std::os::unix::process::parent_id() == maker {
        assert!(Instant::now() < end, "the connection's maker never exited");
        std::thread::sleep(Duration::from_millis(10));
    }
    let id = std::env::var(CHILD_HELD).unwrap();
    common::send_json(
        &mut conn,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "backup.v2.record_result",
            "params": {"id": id, "file": 0, "sha256_after": hex(&[7; 32])}}),
    );
    let answer = match common::read_json(&mut conn) {
        None => json!({"closed": true}),
        Some(v) if v.get("error").is_some() => json!({"err": common::error_kind(&v)}),
        Some(v) => json!({"ok": v["result"]}),
    };
    reply(&json!({"held": answer}));
}

fn worker() {
    let run = RunPaths::under(PathBuf::from(std::env::var_os(CHILD_RUN).unwrap())).unwrap();
    let cs = canaries(std::env::var(CHILD_SEED).unwrap().parse().unwrap());
    let mut plans: std::collections::HashMap<String, (Vec<Spec>, usize, u64)> =
        std::collections::HashMap::new();
    reply(&json!({"ready": true}));
    for line in std::io::stdin().lock().lines() {
        let cmd: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let id = cmd["id"].as_str().unwrap_or_default().to_owned();
        let connect = || Client::connect(&run).unwrap();
        let answer = match cmd["op"].as_str().unwrap() {
            "exit" => break,
            "pid" => json!({"pid": std::process::id()}),
            "move" => {
                // Leaves this terminal for a new session: with a
                // pseudo-terminal of its own, or with none.
                if cmd["to"] == "pty" {
                    envcloak_sys::testing::enter_terminal_session().unwrap();
                } else {
                    envcloak_sys::testing::setsid().unwrap();
                }
                json!({"moved": true})
            }
            "hand_over" => {
                // A connection of this worker's, used once (so the daemon
                // has taken it as this process's), handed to a child of
                // its own as the child's standard input.
                let mut conn = std::os::unix::net::UnixStream::connect(&run.socket).unwrap();
                common::send_json(
                    &mut conn,
                    &json!({"jsonrpc": "2.0", "id": 1, "method": "backup.v2.list", "params": {}}),
                );
                assert!(common::read_json(&mut conn).unwrap()["result"].is_object());
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "backup_v2_child",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD_MODE, "holder")
                    .env(CHILD_HELD, &id)
                    .env(CHILD_MAKER, std::process::id().to_string())
                    .stdin(Stdio::from(std::os::fd::OwnedFd::from(conn)))
                    .spawn()
                    .unwrap();
                json!({"handed": true})
            }
            "begin" => {
                let files: Vec<Spec> = cmd["files"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(Spec::from_json)
                    .collect();
                let claims: Vec<&str> = cmd["claims"]
                    .as_array()
                    .map(|a| a.iter().map(|c| c.as_str().unwrap()).collect())
                    .unwrap_or_default();
                match connect().backup_v2_begin(&begin_params(
                    cmd["purpose"].as_str().unwrap(),
                    &files,
                    &claims,
                )) {
                    Ok(b) => {
                        plans.insert(b.id.clone(), (files, 0, 0));
                        json!({"id": b.id})
                    }
                    Err(e) => err_json(e),
                }
            }
            "put_next" => {
                let (files, f, c) = plans.get_mut(&id).unwrap();
                let data = SecretBytes::from_vec(files[*f].chunk(&cs, *c));
                match connect().backup_v2_put(
                    &id,
                    u32::try_from(*f).unwrap(),
                    u32::try_from(*c).unwrap(),
                    data,
                ) {
                    Ok(p) => {
                        if p.last {
                            *f += 1;
                            *c = 0;
                        } else {
                            *c += 1;
                        }
                        json!({"final": p.last})
                    }
                    Err(e) => err_json(e),
                }
            }
            "put" => {
                let len = usize::try_from(cmd["len"].as_u64().unwrap()).unwrap();
                let data = SecretBytes::from_vec(bytes_at(&cs, 77, 0, len));
                let r = connect().backup_v2_put(
                    &id,
                    u32::try_from(cmd["file"].as_u64().unwrap()).unwrap(),
                    u32::try_from(cmd["chunk"].as_u64().unwrap()).unwrap(),
                    data,
                );
                r.map_or_else(err_json, |p| json!({"final": p.last}))
            }
            "commit" => connect()
                .backup_v2_commit(&id)
                .map_or_else(err_json, |c| json!({"files": c.files})),
            "result" => {
                let mut h = [0u8; 32];
                let hexed = cmd["sha256"].as_str().unwrap();
                for (i, b) in h.iter_mut().enumerate() {
                    *b = u8::from_str_radix(&hexed[2 * i..2 * i + 2], 16).unwrap();
                }
                connect()
                    .backup_v2_record_result(
                        &id,
                        u32::try_from(cmd["file"].as_u64().unwrap()).unwrap(),
                        &h,
                    )
                    .map_or_else(
                        err_json,
                        |r| json!({"recorded": r.recorded, "complete": r.complete}),
                    )
            }
            "list" => connect()
                .backup_v2_list()
                .map_or_else(err_json, |l| serde_json::to_value(l).unwrap()),
            "open" => {
                let pass = SecretBytes::copy_from(cmd["pass"].as_str().unwrap().as_bytes());
                connect()
                    .backup_v2_open_restore(&id, pass, true, true, &[])
                    .map_or_else(err_json, |l| json!({"lease": l.lease}))
            }
            "read" => connect()
                .backup_v2_read(
                    cmd["lease"].as_str().unwrap(),
                    u32::try_from(cmd["file"].as_u64().unwrap()).unwrap(),
                    u32::try_from(cmd["chunk"].as_u64().unwrap()).unwrap(),
                )
                .map_or_else(
                    err_json,
                    |c| json!({"len": c.data.as_secret().len(), "final": c.last}),
                ),
            other => panic!("unknown command {other}"),
        };
        reply(&answer);
    }
}

/// The paths a backup v2 takes and the caps it refuses at (docs/IPC.md
/// "Backups v2"): a path outside the allowed roots, a relative one and
/// one with `..` are `invalid_params`, as is an unknown purpose; a 300 MiB
/// file, a backup over 1 GiB and one of 4,097 files are `too_large`,
/// before anything is begun; and there is no field for the creator: a
/// request that sends one is `invalid_params`, and so is one with any
/// other field it does not know.
#[test]
fn only_allowed_paths_and_sizes_are_taken_and_no_client_names_the_creator() {
    let f = Fixture::new();
    let home = f.home.home();
    let ok = Spec::made(&f.claude("settings.json"), 10, 1);
    for bad in [
        home.join(".zshrc"),
        home.join(".ssh/config"),
        home.join("Library/LaunchAgents/evil.plist"),
        home.join(".claude/../.zshrc"),
        PathBuf::from("relative/.claude/settings.json"),
        PathBuf::from("/etc/passwd"),
    ] {
        let e = client(&f.home)
            .backup_v2_begin(&begin_params(
                "scrub",
                &[ok.clone(), Spec::made(&bad, 10, 1)],
                &[],
            ))
            .unwrap_err();
        assert_eq!(rpc(e), (ErrorKind::InvalidParams, None), "{bad:?}");
    }
    let e = client(&f.home)
        .backup_v2_begin(&begin_params("bake", std::slice::from_ref(&ok), &[]))
        .unwrap_err();
    assert_eq!(rpc(e).0, ErrorKind::InvalidParams);
    let big = |n: u64| Spec::made(&f.claude("projects/p/big.jsonl"), n, 1);
    for files in [
        vec![big(300 * MIB)],
        vec![big(256 * MIB); 5],
        vec![big(0); 4097],
    ] {
        let e = client(&f.home)
            .backup_v2_begin(&begin_params("scrub", &files, &[]))
            .unwrap_err();
        assert_eq!(rpc(e), (ErrorKind::FilesBackupFailed, Some("too_large")));
    }
    // A creator, or anything else the method does not take, in the request.
    for extra in [
        json!({"creator": {"kind": "terminal", "pid": 1}}),
        json!({"creator_kind": "terminal"}),
        json!({"owner": 1}),
    ] {
        let mut params =
            serde_json::to_value(begin_params("scrub", std::slice::from_ref(&ok), &[])).unwrap();
        for (k, v) in extra.as_object().unwrap() {
            params[k] = v.clone();
        }
        let mut s = common::raw(&f.home);
        common::send_json(
            &mut s,
            &json!({"jsonrpc": "2.0", "id": 1, "method": "backup.v2.begin", "params": params}),
        );
        let answer = common::read_json(&mut s).unwrap();
        assert_eq!(common::error_kind(&answer), "invalid_params", "{extra}");
    }
    assert!(f.list().backups.is_empty());
    let staging = data_dir(&f.home).join("backups");
    assert!(!staging.exists() || std::fs::read_dir(&staging).unwrap().next().is_none());
    f.sweep();
}

/// Byte for byte at 0 bytes, 1 byte, exactly 1 MiB and 1 MiB plus one,
/// through `begin`, `put` (a fresh connection each), `commit`, one proof
/// and reads under the lease; the backup lists as made by this terminal
/// for `scrub`; the statement says "created by you (terminal)". The
/// backups directory, the daemon's temporary directory and its log hold
/// no fixture.
#[test]
fn a_backup_comes_back_byte_for_byte() {
    let f = Fixture::new();
    let files: Vec<Spec> = [0, 1, MIB, MIB + 1]
        .iter()
        .enumerate()
        .map(|(i, n)| Spec::made(&f.claude(&format!("projects/p/s{i}.jsonl")), *n, i as u8))
        .collect();
    let id = f.backup("scrub", &files);
    for (i, s) in files.iter().enumerate() {
        let r = client(&f.home)
            .backup_v2_record_result(&id, u32::try_from(i).unwrap(), &s.sha(f.files_cs()))
            .unwrap();
        assert_eq!(r.complete, i + 1 == files.len());
    }
    let l = f.list();
    assert_eq!(l.backups.len(), 1);
    let b = &l.backups[0];
    assert_eq!(b.id, id);
    assert_eq!(b.state, BackupStateView::Complete);
    assert_eq!(b.purpose.as_deref(), Some("scrub"));
    assert_eq!(b.creator.as_ref().unwrap().kind, "terminal");
    let lease = f.open(&id, false, false).unwrap();
    assert!(
        lease
            .statement
            .lines()
            .iter()
            .any(|l| l == "created by you (terminal)")
    );
    read_back(&f.paths(), f.files_cs(), &lease, &files);
    assert_eq!(f.list().open_leases, 1);
    f.sweep();
}

/// A 200 MiB file: uploaded and read back byte for byte with one proof
/// (`open_restore` is the only call that carries the passphrase), one
/// Argon2id run (the daemon's test trace counts them) and one audit entry
/// of kind `restore_v2`, while the daemon's resident memory grows by far
/// less than the file: it holds one chunk at a time.
#[test]
fn a_200_mib_file_takes_one_proof_and_one_audit_entry_in_bounded_memory() {
    let mut f = Fixture::new();
    let files = [Spec::made(&f.claude("projects/p/huge.jsonl"), 200 * MIB, 9)];
    let before = common::rss_kib(f.d.pid());
    let id = f.backup("scrub", &files);
    client(&f.home)
        .backup_v2_record_result(&id, 0, &files[0].sha(f.files_cs()))
        .unwrap();
    let lease = f.open(&id, false, false).unwrap();
    read_back(&f.paths(), f.files_cs(), &lease, &files);
    let grew = common::rss_kib(f.d.pid()).saturating_sub(before);
    assert!(grew < 64 * 1024, "the daemon grew by {grew} KiB");
    let entries = f.audit_after_stop();
    // The daemon's whole log, read once it has exited: the unlock's run
    // and the restore's, no more.
    let runs = String::from_utf8_lossy(&f.d.log_bytes())
        .lines()
        .filter(|l| l.contains("envcloak test: argon2id run"))
        .count();
    assert_eq!(runs, 2, "Argon2id runs: the unlock's and one restore's");
    let restores: Vec<_> = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::RestoreV2)
        .collect();
    assert_eq!(restores.len(), 1);
    assert_eq!(restores[0].record.decision.outcome, "opened");
    assert_eq!(restores[0].record.request_id.as_deref(), Some(id.as_str()));
    let commits = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::BackupV2)
        .count();
    assert_eq!(commits, 1);
    f.sweep();
}

/// Upload ownership (Codex cycle173 proposal 2): two clients under one
/// agent root, A and B, interleaved at every upload call, one call at a
/// time. A begins; B puts into A's id, commits it and records a result,
/// before and after A commits, each refused `not_backup_owner`, while A's
/// own calls succeed; B lists the id once it is committed. The backup's
/// creator, its contents (SHA-256 per file) and its recorded results are
/// exactly A's. Then a `put` and a `commit` after A's commit, and a
/// second result, are refused `backup_frozen` to A. Restored from this
/// terminal (another session than the agent's) with `--created-by-agent`.
#[test]
fn only_the_process_that_began_a_backup_may_add_to_it() {
    let f = Fixture::new();
    let cs = f.files_cs();
    let files = [
        Spec::made(&f.claude("projects/p/a.jsonl"), MIB + 7, 11),
        Spec::made(&f.claude("projects/p/b.jsonl"), 3, 12),
    ];
    let mut pair = f.child("pair", true);
    let a_pid = pair.ask(json!({"to": "A", "op": "pid"}))["pid"]
        .as_i64()
        .unwrap();
    let begun = pair.ask(json!({"to": "A", "op": "begin", "purpose": "scrub",
        "files": files.iter().map(Spec::to_json).collect::<Vec<_>>()}));
    let id = begun["id"].as_str().unwrap().to_owned();
    let b = |pair: &mut Worker, op: Value| {
        let mut cmd = op;
        cmd["to"] = json!("B");
        cmd["id"] = json!(id.clone());
        pair.ask(cmd)
    };
    let refused = |v: Value, what: &str| assert_eq!(err(&v), "not_backup_owner", "{what}: {v}");
    // In progress: never listed, and B is refused at every call.
    assert!(
        b(&mut pair, json!({"op": "list"}))["backups"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    refused(
        b(
            &mut pair,
            json!({"op": "put", "file": 0, "chunk": 0, "len": CHUNK_V2}),
        ),
        "B put before A",
    );
    assert_eq!(
        pair.ask(json!({"to": "A", "op": "put_next", "id": id}))["final"],
        false
    );
    refused(b(&mut pair, json!({"op": "commit"})), "B commit");
    refused(
        b(
            &mut pair,
            json!({"op": "put", "file": 0, "chunk": 1, "len": CHUNK_V2}),
        ),
        "B put between",
    );
    assert_eq!(
        pair.ask(json!({"to": "A", "op": "put_next", "id": id}))["final"],
        false
    );
    refused(
        b(
            &mut pair,
            json!({"op": "result", "file": 0, "sha256": hex(&[1; 32])}),
        ),
        "B result early",
    );
    assert_eq!(
        pair.ask(json!({"to": "A", "op": "put_next", "id": id}))["final"],
        true
    );
    assert_eq!(
        pair.ask(json!({"to": "A", "op": "put_next", "id": id}))["final"],
        true
    );
    assert_eq!(
        pair.ask(json!({"to": "A", "op": "commit", "id": id}))["files"],
        2
    );
    // Committed: B lists it, and is still refused, learning nothing more.
    let listed = b(&mut pair, json!({"op": "list"}));
    assert_eq!(listed["backups"][0]["id"], json!(id));
    refused(
        b(
            &mut pair,
            json!({"op": "put", "file": 0, "chunk": 0, "len": CHUNK_V2}),
        ),
        "B put after",
    );
    refused(b(&mut pair, json!({"op": "commit"})), "B commit after");
    refused(
        b(
            &mut pair,
            json!({"op": "result", "file": 0, "sha256": hex(&[1; 32])}),
        ),
        "B result",
    );
    let after = [
        Sha256::digest(b"what A's scrub left in a"),
        Sha256::digest(b"and in b"),
    ];
    for (i, h) in after.iter().enumerate() {
        let r = pair.ask(json!({"to": "A", "op": "result", "id": id, "file": i, "sha256": hex(h)}));
        assert!(r.get("recorded").is_some(), "{r}");
    }
    // Frozen, and one result per file, for A too.
    let frozen = |v: Value| assert_eq!(err(&v), "backup_frozen", "{v}");
    frozen(
        pair.ask(json!({"to": "A", "op": "result", "id": id, "file": 0, "sha256": hex(&[2; 32])})),
    );
    frozen(
        pair.ask(json!({"to": "A", "op": "put", "id": id, "file": 0, "chunk": 0, "len": CHUNK_V2})),
    );
    frozen(pair.ask(json!({"to": "A", "op": "commit", "id": id})));
    pair.end();

    let l = f.list();
    assert_eq!(l.backups.len(), 1);
    let entry = &l.backups[0];
    assert_eq!(entry.state, BackupStateView::Complete);
    let creator = entry.creator.as_ref().unwrap();
    assert_eq!(
        (creator.kind.as_str(), creator.agent.as_deref()),
        ("agent", Some(AGENT_NAME))
    );
    assert_eq!(i64::from(creator.pid), a_pid);
    let lease = f.open(&id, true, false).unwrap();
    for (i, h) in after.iter().enumerate() {
        assert_eq!(
            lease.statement.files[i].sha256_after.as_deref(),
            Some(hex(h).as_str())
        );
    }
    read_back(&f.paths(), cs, &lease, &files);
    f.sweep();
}

/// A creator that exits before recording its results leaves the backup
/// `result_unrecorded`: listed so, its statement says EnvCloak does not
/// know what the change left, a plain restore is refused
/// (`restore_refused`, `result_unrecorded`) before the passphrase is
/// looked at, and the recovery form `unrecorded` restores it after the
/// proof.
#[test]
fn a_creator_that_exits_first_leaves_result_unrecorded() {
    let f = Fixture::new();
    let files = [Spec::made(&f.home.home().join("acme/.env"), 40, 3)];
    let mut w = f.child("worker", false);
    let id = w.ask(json!({"op": "begin", "purpose": "scrub",
        "files": files.iter().map(Spec::to_json).collect::<Vec<_>>()}))["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(w.ask(json!({"op": "put_next", "id": id}))["final"], true);
    assert_eq!(w.ask(json!({"op": "commit", "id": id}))["files"], 1);
    assert_eq!(f.list().backups[0].state, BackupStateView::AwaitingResult);
    w.end();
    assert_eq!(f.list().backups[0].state, BackupStateView::ResultUnrecorded);
    let before = client(&f.home).status().unwrap().vault.failed_unlocks;
    let e = f.open(&id, false, false).unwrap_err();
    assert_eq!(
        rpc(e),
        (ErrorKind::RestoreRefused, Some("result_unrecorded"))
    );
    // Refused before the passphrase: a wrong one changes nothing either.
    let e = client(&f.home)
        .backup_v2_open_restore(
            &id,
            SecretBytes::copy_from(b"not it at all"),
            false,
            false,
            &[],
        )
        .unwrap_err();
    assert_eq!(rpc(e).0, ErrorKind::RestoreRefused);
    assert_eq!(
        client(&f.home).status().unwrap().vault.failed_unlocks,
        before
    );
    let lease = f.open(&id, false, true).unwrap();
    assert_eq!(lease.statement.state, BackupStateView::ResultUnrecorded);
    assert!(
        lease
            .statement
            .lines()
            .iter()
            .any(|l| l.contains("does not know what the change left"))
    );
    assert_eq!(lease.statement.files[0].sha256_after, None);
    read_back(&f.paths(), f.files_cs(), &lease, &files);
    f.sweep();
}

/// An agent backs up `~/.claude/settings.json` holding a planted hook,
/// from another terminal window: the backup records the agent, never the
/// client's word; the restore statement names the agent ("this backup was
/// created by ..., not by you"); a restore without `--created-by-agent`
/// is refused before the passphrase; with it, the hook comes back as
/// backed up. A restore from an agent subject, and from a process with
/// no terminal, is refused (`proof_refused`) whatever the tick.
#[test]
fn an_agents_backup_is_named_and_needs_the_tick() {
    let f = Fixture::new();
    let hook = br#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"sh ~/.cache/x.sh"}]}]}}"#;
    let settings = Spec {
        path: f.claude("settings.json").to_str().unwrap().to_owned(),
        size: hook.len() as u64,
        salt: 0,
        text: Some(hook.to_vec()),
    };
    let mut agent = f.child("worker", true);
    let id = agent.ask(json!({"op": "begin", "purpose": "agents", "files": [settings.to_json()]}))
        ["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        agent.ask(json!({"op": "put_next", "id": id}))["final"],
        true
    );
    assert_eq!(agent.ask(json!({"op": "commit", "id": id}))["files"], 1);
    let r = agent
        .ask(json!({"op": "result", "id": id, "file": 0, "sha256": hex(&Sha256::digest(b"{}"))}));
    assert_eq!(r["complete"], true, "{r}");
    let e = f.open(&id, false, false).unwrap_err();
    assert_eq!(
        rpc(e),
        (ErrorKind::RestoreRefused, Some("created_by_agent"))
    );
    // Not from an agent, nor from a process without a terminal.
    let e = client(&f.home)
        .backup_v2_open_restore(&id, passphrase(&f.cs), true, false, &[AGENT.to_owned()])
        .unwrap_err();
    assert_eq!(rpc(e).0, ErrorKind::ProofRefused);
    let mut notty = f.child("notty", false);
    let r = notty.ask(json!({"op": "open", "id": id, "pass": f.pass()}));
    assert_eq!(err(&r), "proof_refused", "{r}");
    notty.end();
    let lease = f.open(&id, true, false).unwrap();
    let st = &lease.statement;
    assert_eq!(st.creator.kind, "agent");
    assert_eq!(st.creator.agent.as_deref(), Some(AGENT_NAME));
    assert_eq!(st.purpose, "agents");
    let words = st.lines();
    assert!(
        words.contains(&format!(
            "this backup was created by {AGENT_NAME}, not by you"
        )),
        "{words:?}"
    );
    read_back(&f.paths(), f.files_cs(), &lease, &[settings]);
    agent.end();
    f.sweep();
}

/// A restore lease serves only its own process: another process on the
/// same terminal is refused (`no_such_lease`) with the lease's id, as is
/// a malformed id. A lock ends every lease. A lease whose process exits
/// ends with it (the daemon's sweep, within seconds).
#[test]
fn a_lease_serves_only_its_process_until_lock_or_its_exit() {
    let f = Fixture::new();
    let files = [Spec::made(&f.claude("projects/p/l.jsonl"), 100, 4)];
    let id = f.backup("scrub", &files);
    let lease = f.open(&id, false, true).unwrap();
    let mut other = f.child("worker", false);
    let r = other.ask(json!({"op": "read", "lease": lease.lease, "file": 0, "chunk": 0}));
    assert_eq!(err(&r), "no_such_lease", "{r}");
    // The lease still serves its own process.
    read_back(&f.paths(), f.files_cs(), &lease, &files);
    let e = client(&f.home)
        .backup_v2_read("not-a-lease", 0, 0)
        .unwrap_err();
    assert_eq!(rpc(e).0, ErrorKind::NoSuchLease);

    // A lease opened by another process ends when it exits.
    let r = other.ask(json!({"op": "open", "id": id, "pass": f.pass()}));
    let theirs = r["lease"]
        .as_str()
        .unwrap_or_else(|| panic!("{r}"))
        .to_owned();
    let r = other.ask(json!({"op": "read", "lease": theirs, "file": 0, "chunk": 0}));
    assert_eq!(r["len"], 100, "{r}");
    assert_eq!(f.list().open_leases, 2);
    other.end();
    let end = Instant::now() + Duration::from_secs(10);
    while f.list().open_leases != 1 {
        assert!(
            Instant::now() < end,
            "the exited process's lease is still open"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // A lock ends every lease.
    client(&f.home).lock().unwrap();
    client(&f.home).unlock(passphrase(&f.cs), &[]).unwrap();
    let e = client(&f.home)
        .backup_v2_read(&lease.lease, 0, 0)
        .unwrap_err();
    assert_eq!(rpc(e).0, ErrorKind::NoSuchLease);
    assert_eq!(f.list().open_leases, 0);
    f.sweep();
}

/// Gate 33's order for a restore: when the lease's audit entry cannot be
/// written (another program put a file where the log's directory was),
/// `open_restore` is `audit_failed`, no lease exists and no chunk can be
/// read; once the log can be written, the lease's entry is on disk before
/// its answer, so before the first chunk: the daemon is killed right
/// after the answer, and the entry is in the log.
#[test]
fn no_lease_without_its_audit_entry_on_disk_first() {
    let mut f = Fixture::new();
    let files = [Spec::made(&f.claude("projects/p/a.jsonl"), 5000, 5)];
    let id = f.backup("scrub", &files);
    client(&f.home)
        .backup_v2_record_result(&id, 0, &files[0].sha(f.files_cs()))
        .unwrap();
    let audit = data_dir(&f.home).join("audit");
    std::fs::remove_dir_all(&audit).unwrap();
    std::fs::write(&audit, b"in the way").unwrap();
    let e = f.open(&id, false, false).unwrap_err();
    assert_eq!(rpc(e).0, ErrorKind::AuditFailed);
    assert_eq!(f.list().open_leases, 0);
    std::fs::remove_file(&audit).unwrap();
    std::fs::create_dir(&audit).unwrap();
    std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o700)).unwrap();
    let lease = f.open(&id, false, false).unwrap();
    f.d.signal("-KILL");
    assert!(f.d.wait_exit(Duration::from_secs(30)).is_some());
    let entries = f.read_audit();
    let opened: Vec<_> = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::RestoreV2 && e.record.decision.outcome == "opened")
        .collect();
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].record.request_id.as_deref(), Some(id.as_str()));
    drop(lease);
    f.sweep();
}

/// A backup that does not open whole releases nothing: with one of its
/// chunks altered, two swapped or its end cut, `open_restore` is
/// `files_backup_failed` and no lease exists; put back, it restores.
#[test]
fn a_damaged_backup_releases_nothing() {
    let f = Fixture::new();
    let files = [Spec::made(
        &f.claude("projects/p/d.jsonl"),
        3 * CHUNK_V2 as u64,
        6,
    )];
    let id = f.backup("scrub", &files);
    client(&f.home)
        .backup_v2_record_result(&id, 0, &files[0].sha(f.files_cs()))
        .unwrap();
    let dir = std::fs::read_dir(data_dir(&f.home).join("backups"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_name().unwrap().to_str().unwrap().ends_with(&id))
        .unwrap();
    let data = dir.join("data");
    let good = std::fs::read(&data).unwrap();
    let key_len = u32::from_be_bytes(good[51..55].try_into().unwrap()) as usize;
    let first = 51 + 4 + key_len;
    let rec = 4 + CHUNK_V2 + 40;
    let mut altered = good.clone();
    altered[first + rec + 100] ^= 1;
    let mut swapped = good.clone();
    swapped[first..first + rec].copy_from_slice(&good[first + rec..first + 2 * rec]);
    swapped[first + rec..first + 2 * rec].copy_from_slice(&good[first..first + rec]);
    for (what, bytes) in [
        ("altered", altered),
        ("swapped", swapped),
        ("cut", good[..good.len() - 20].to_vec()),
    ] {
        std::fs::write(&data, &bytes).unwrap();
        let e = f.open(&id, false, false).unwrap_err();
        assert_eq!(rpc(e).0, ErrorKind::FilesBackupFailed, "{what}");
        assert_eq!(f.list().open_leases, 0, "{what}");
    }
    std::fs::write(&data, &good).unwrap();
    let lease = f.open(&id, false, false).unwrap();
    read_back(&f.paths(), f.files_cs(), &lease, &files);
    f.sweep();
}

/// `kill -9` of the client between its calls, and of the daemon with a
/// backup in progress, leaves no listed partial backup: the killed
/// client's backup is dropped (its staging directory removed) by the
/// daemon's sweep, and a restarted daemon lists nothing.
#[test]
fn a_killed_client_or_daemon_leaves_no_listed_partial_backup() {
    let mut f = Fixture::new();
    let files = [Spec::made(&f.claude("projects/p/k.jsonl"), 2 * MIB, 7)];
    let backups = data_dir(&f.home).join("backups");
    let staging = || {
        std::fs::read_dir(&backups).map_or(0, |d| {
            d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(".files2-"))
                .count()
        })
    };
    for steps in [0, 1, 3] {
        let mut w = f.child("worker", false);
        let begun = w.ask(json!({"op": "begin", "purpose": "scrub",
            "files": files.iter().map(Spec::to_json).collect::<Vec<_>>()}));
        let id = begun["id"].as_str().unwrap().to_owned();
        for _ in 0..steps {
            assert_eq!(w.ask(json!({"op": "put_next", "id": id}))["final"], false);
        }
        assert_eq!(staging(), 1);
        let _ = w.child.kill();
        w.child.wait().unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        while staging() != 0 {
            assert!(Instant::now() < end, "the killed client's backup was kept");
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(f.list().backups.is_empty());
        let e = client(&f.home).backup_v2_commit(&id).unwrap_err();
        assert_eq!(rpc(e).0, ErrorKind::NoSuchBackup);
    }
    // The daemon killed with a backup in progress.
    let id = client(&f.home)
        .backup_v2_begin(&begin_params("scrub", &files, &[]))
        .unwrap()
        .id;
    client(&f.home)
        .backup_v2_put(
            &id,
            0,
            0,
            SecretBytes::from_vec(files[0].chunk(f.files_cs(), 0)),
        )
        .unwrap();
    f.d.signal("-KILL");
    assert!(f.d.wait_exit(Duration::from_secs(30)).is_some());
    f.d = Fixture::daemon(&f.home);
    client(&f.home).unlock(passphrase(&f.cs), &[]).unwrap();
    assert_eq!(
        client(&f.home).status().unwrap().vault.state,
        VaultState::Unlocked
    );
    assert!(f.list().backups.is_empty());
    let e = client(&f.home).backup_v2_commit(&id).unwrap_err();
    assert_eq!(rpc(e).0, ErrorKind::NoSuchBackup);
    f.sweep();
}

/// The approval-origin boundary for a restore (T9-3, F-70): a backup an
/// agent made on this very terminal is not restored from that terminal
/// or its session while the agent still runs (`proof_refused`,
/// `requester_terminal`), tick or not: the agent could read what is
/// typed there, or be what types it. The creator's chain is sealed with
/// the backup, so this holds after a restart of the daemon too. Once the
/// agent has exited, the person restores it there.
#[test]
fn an_agents_backup_is_not_restored_from_the_agents_terminal() {
    let mut f = Fixture::new();
    let files = [Spec::made(&f.claude("settings.local.json"), 64, 8)];
    let mut agent = f.agent_here();
    let begun = agent.ask(json!({"op": "begin", "purpose": "agents",
        "files": files.iter().map(Spec::to_json).collect::<Vec<_>>()}));
    let id = begun["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{begun}"))
        .to_owned();
    assert_eq!(
        agent.ask(json!({"op": "put_next", "id": id}))["final"],
        true
    );
    assert_eq!(agent.ask(json!({"op": "commit", "id": id}))["files"], 1);
    let r = agent.ask(json!({"op": "result", "id": id, "file": 0, "sha256": hex(&[3; 32])}));
    assert_eq!(r["complete"], true, "{r}");
    let e = f.open(&id, true, false).unwrap_err();
    assert_eq!(
        rpc(e),
        (ErrorKind::ProofRefused, Some("requester_terminal"))
    );
    assert_eq!(f.list().open_leases, 0);
    // A daemon that did not see the backup begin reads the chain from it.
    f.restart();
    let e = f.open(&id, true, false).unwrap_err();
    assert_eq!(
        rpc(e),
        (ErrorKind::ProofRefused, Some("requester_terminal")),
        "after a restart"
    );
    assert_eq!(f.list().open_leases, 0);
    agent.end();
    let lease = f.open(&id, true, false).unwrap();
    assert_eq!(lease.statement.creator.kind, "agent");
    read_back(&f.paths(), f.files_cs(), &lease, &files);
    f.sweep();
}

/// The proof-origin check comes first and stands alone (SPEC §10b, L-10):
/// a backup this terminal made, its results all recorded, is not
/// restored by a caller that says it is an agent, by an agent in a
/// terminal of its own, nor by a process without a terminal, tick or
/// not. After a restart of the daemon the same holds for a backup the
/// agent made. Each refusal is `proof_refused`, audited with the method,
/// and leaves no lease; the person then restores both from this terminal.
#[test]
fn a_restore_is_refused_to_an_agent_and_to_a_process_without_a_terminal() {
    let mut f = Fixture::new();
    let files = [Spec::made(&f.claude("projects/p/t.jsonl"), 300, 13)];
    let id = f.backup("scrub", &files);
    client(&f.home)
        .backup_v2_record_result(&id, 0, &files[0].sha(f.files_cs()))
        .unwrap();
    let mut agent = f.child("worker", true);
    let mut notty = f.child("notty", false);
    let refused_everywhere = |f: &Fixture, agent: &mut Worker, notty: &mut Worker, id: &str| {
        let e = client(&f.home)
            .backup_v2_open_restore(id, passphrase(&f.cs), true, true, &[AGENT.to_owned()])
            .unwrap_err();
        assert_eq!(rpc(e).0, ErrorKind::ProofRefused, "claimed agent");
        for (who, w) in [("agent", agent), ("no terminal", notty)] {
            let r = w.ask(json!({"op": "open", "id": id, "pass": f.pass()}));
            assert_eq!(err(&r), "proof_refused", "{who}: {r}");
        }
        assert_eq!(f.list().open_leases, 0);
    };
    refused_everywhere(&f, &mut agent, &mut notty, &id);

    let settings = Spec::made(&f.claude("settings.json"), 50, 14);
    let theirs = agent.ask(json!({"op": "begin", "purpose": "agents",
        "files": [settings.to_json()]}))["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        agent.ask(json!({"op": "put_next", "id": theirs}))["final"],
        true
    );
    assert_eq!(agent.ask(json!({"op": "commit", "id": theirs}))["files"], 1);
    let r = agent.ask(json!({"op": "result", "id": theirs, "file": 0, "sha256": hex(&[5; 32])}));
    assert_eq!(r["complete"], true, "{r}");
    f.restart();
    refused_everywhere(&f, &mut agent, &mut notty, &theirs);
    agent.end();
    notty.end();

    let lease = f.open(&id, false, false).unwrap();
    read_back(&f.paths(), f.files_cs(), &lease, &files);
    let lease = f.open(&theirs, true, false).unwrap();
    read_back(&f.paths(), f.files_cs(), &lease, &[settings]);
    let entries = f.audit_after_stop();
    let refusals = entries
        .iter()
        .filter(|e| {
            e.record.kind == AuditKind::ProofRefused
                && e.record.decision.method.as_deref() == Some("backup.v2.open_restore")
        })
        .count();
    assert_eq!(refusals, 6);
    f.sweep();
}

/// A connection outlives the process that made it when the descriptor is
/// handed on: the creator of a committed backup passes one of its
/// connections to a child and exits before recording a result. The child
/// then records one on it, and is refused: on Linux the daemon still
/// names the creator on that connection, which has exited
/// (`not_backup_owner`); on macOS it closes the connection, whose peer
/// changed. The backup stays `result_unrecorded`.
#[test]
fn a_connection_handed_on_does_not_act_for_a_creator_that_exited() {
    let f = Fixture::new();
    let files = [Spec::made(&f.home.home().join("acme/.env"), 20, 15)];
    let mut w = f.child("worker", false);
    let id = w.ask(json!({"op": "begin", "purpose": "scrub",
        "files": files.iter().map(Spec::to_json).collect::<Vec<_>>()}))["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(w.ask(json!({"op": "put_next", "id": id}))["final"], true);
    assert_eq!(w.ask(json!({"op": "commit", "id": id}))["files"], 1);
    assert_eq!(w.ask(json!({"op": "hand_over", "id": id}))["handed"], true);
    let _ = writeln!(w.stdin, "{}", json!({"op": "exit"}));
    w.child.wait().unwrap();
    let held = read_reply(&mut w.out)["held"].clone();
    let refused = held["err"] == "not_backup_owner" || held["closed"] == true;
    assert!(refused, "the handed-on connection acted: {held}");
    let l = f.list();
    assert_eq!(l.backups[0].state, BackupStateView::ResultUnrecorded);
    let lease = f.open(&id, false, true).unwrap();
    assert_eq!(lease.statement.files[0].sha256_after, None);
    f.sweep();
}

/// A lock stops a call already in flight (SPEC "Lock"; D-07): the daemon
/// is stopped by a barrier in `read` after it decrypted a chunk, in `put`
/// after it wrote one and in `commit` after the metadata is sealed and
/// before the backup is put in place, and the vault is locked meanwhile.
/// The read then delivers nothing (`no_such_lease`), the put and the
/// commit report the backup ended, and after the next unlock no backup
/// is listed or left in `backups/`, staging directories included.
#[test]
fn a_lock_stops_a_call_in_flight() {
    for site in ["backup.v2.read", "backup.v2.put", "backup.v2.commit"] {
        let mut f = Fixture::pausing(Some(site));
        let files = [Spec::made(&f.claude("projects/p/f.jsonl"), 3000, 16)];
        let cs: Vec<Canary> = f.files_cs().to_vec();
        let paths = f.paths();
        let begin = || {
            client(&f.home)
                .backup_v2_begin(&begin_params("scrub", &files, &[]))
                .unwrap()
                .id
        };
        let in_flight: std::thread::JoinHandle<Result<(), ClientError>> = match site {
            "backup.v2.read" => {
                let id = begin();
                put_all(&paths, &cs, &id, &files).unwrap();
                client(&f.home).backup_v2_commit(&id).unwrap();
                let lease = f.open(&id, false, true).unwrap().lease;
                std::thread::spawn(move || {
                    Client::connect(&paths)?
                        .backup_v2_read(&lease, 0, 0)
                        .map(drop)
                })
            }
            "backup.v2.put" => {
                let id = begin();
                let data = SecretBytes::from_vec(files[0].chunk(&cs, 0));
                std::thread::spawn(move || {
                    Client::connect(&paths)?
                        .backup_v2_put(&id, 0, 0, data)
                        .map(drop)
                })
            }
            _ => {
                let id = begin();
                put_all(&paths, &cs, &id, &files).unwrap();
                std::thread::spawn(move || Client::connect(&paths)?.backup_v2_commit(&id).map(drop))
            }
        };
        f.wait_paused(site);
        client(&f.home).lock().unwrap();
        f.release();
        let e = in_flight
            .join()
            .unwrap()
            .err()
            .unwrap_or_else(|| panic!("{site}: the call in flight went through the lock"));
        let (kind, _) = rpc(e);
        let ended = [
            ErrorKind::NoSuchLease,
            ErrorKind::NoSuchBackup,
            ErrorKind::VaultLocked,
        ];
        assert!(ended.contains(&kind), "{site}: {kind:?}");
        client(&f.home).unlock(passphrase(&f.cs), &[]).unwrap();
        let l = f.list();
        let backups = data_dir(&f.home).join("backups");
        let left: Vec<String> = std::fs::read_dir(&backups)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        if site == "backup.v2.read" {
            assert_eq!((l.backups.len(), l.open_leases), (1, 0), "{site}");
        } else {
            assert!(l.backups.is_empty(), "{site}: {l:?}");
            assert!(left.is_empty(), "{site}: {left:?}");
        }
        f.sweep();
    }
}

/// A lease is bound to the terminal its proof came from (D-07): a process
/// that opened one and then moved to another terminal (a new session on a
/// pseudo-terminal of its own), or to none, is the same process instance
/// but gets `no_such_lease` with it, whatever chunk it asks for.
#[test]
fn a_lease_serves_only_the_terminal_of_its_proof() {
    let f = Fixture::new();
    let files = [Spec::made(&f.claude("projects/p/m.jsonl"), 100, 17)];
    let id = f.backup("scrub", &files);
    for to in ["pty", "none"] {
        let mut w = f.child("worker", false);
        let r = w.ask(json!({"op": "open", "id": id, "pass": f.pass()}));
        let lease = r["lease"]
            .as_str()
            .unwrap_or_else(|| panic!("{r}"))
            .to_owned();
        let r = w.ask(json!({"op": "read", "lease": lease, "file": 0, "chunk": 0}));
        assert_eq!(r["len"], 100, "{to}: {r}");
        assert_eq!(w.ask(json!({"op": "move", "to": to}))["moved"], true);
        let r = w.ask(json!({"op": "read", "lease": lease, "file": 0, "chunk": 0}));
        assert_eq!(err(&r), "no_such_lease", "{to}: {r}");
        w.end();
    }
    f.sweep();
}

/// A backup keeps a file's permission bits only: the set-user-id,
/// set-group-id and sticky bits a client declares are dropped, so a
/// restore is never handed one to set.
#[test]
fn a_backup_keeps_only_permission_bits() {
    let f = Fixture::new();
    let modes = [0o4755, 0o2700, 0o1777, 0o7640, 0o640];
    let files: Vec<Spec> = (0..modes.len())
        .map(|i| Spec::made(&f.claude(&format!("projects/p/m{i}.jsonl")), 10, 18))
        .collect();
    let mut params = begin_params("scrub", &files, &[]);
    for (p, m) in params.files.iter_mut().zip(modes) {
        p.mode = m;
    }
    let id = client(&f.home).backup_v2_begin(&params).unwrap().id;
    put_all(&f.paths(), f.files_cs(), &id, &files).unwrap();
    client(&f.home).backup_v2_commit(&id).unwrap();
    let lease = f.open(&id, false, true).unwrap();
    let kept: Vec<u32> = lease.statement.files.iter().map(|v| v.mode).collect();
    assert_eq!(kept, [0o755, 0o700, 0o777, 0o640, 0o640]);
    f.sweep();
}

/// One root holds at most four backups in progress, so no agent can take
/// every slot: a fifth `begin` from this terminal's session, this process
/// or another process in the session, is `busy` (back off), while an
/// agent in a terminal of its own still begins one; once one of the
/// session's is committed, it begins again.
#[test]
fn one_root_holds_at_most_four_backups_in_progress() {
    let f = Fixture::new();
    let files = [Spec::made(&f.home.home().join("acme/.env"), 5, 19)];
    let begin = || client(&f.home).backup_v2_begin(&begin_params("scrub", &files, &[]));
    let ids: Vec<String> = (0..4).map(|_| begin().unwrap().id).collect();
    assert_eq!(rpc(begin().unwrap_err()).0, ErrorKind::Busy);
    let ask_begin = json!({"op": "begin", "purpose": "scrub", "files": [files[0].to_json()]});
    let mut here = f.child("worker", false);
    let r = here.ask(ask_begin.clone());
    assert_eq!(err(&r), "busy", "{r}");
    let mut agent = f.child("worker", true);
    let r = agent.ask(ask_begin);
    assert!(r["id"].is_string(), "{r}");
    put_all(&f.paths(), f.files_cs(), &ids[0], &files).unwrap();
    client(&f.home).backup_v2_commit(&ids[0]).unwrap();
    begin().unwrap();
    here.end();
    agent.end();
    f.sweep();
}

/// `list` opens the backups outside the daemon's state lock: stopped by a
/// barrier after it opened one, the daemon still answers `status` and
/// takes a `lock` meanwhile. The list then ends `vault_locked`, as a lock
/// ends any call in flight.
#[test]
fn a_list_holds_no_lock_while_it_opens_backups() {
    let mut f = Fixture::pausing(Some("backup.v2.list"));
    let files = [Spec::made(&f.claude("projects/p/l.jsonl"), 40, 20)];
    f.backup("scrub", &files);
    let paths = f.paths();
    let listing = std::thread::spawn(move || Client::connect(&paths)?.backup_v2_list().map(drop));
    f.wait_paused("backup.v2.list");
    let (tx, rx) = std::sync::mpsc::channel();
    let paths = f.paths();
    std::thread::spawn(move || {
        let state = Client::connect(&paths).and_then(|mut c| c.status());
        let _ = tx.send(state.map(|s| s.vault.state));
    });
    let state = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("status waited for the list");
    assert_eq!(state.unwrap(), VaultState::Unlocked);
    client(&f.home).lock().unwrap();
    f.release();
    let e = listing.join().unwrap().unwrap_err();
    assert_eq!(rpc(e).0, ErrorKind::VaultLocked);
    f.sweep();
}
