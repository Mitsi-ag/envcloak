//! What the managed-server tests share (M2 plan task M2-27): the helper
//! this test binary runs as when started again with [`HELPER`] set, and a
//! [`World`]: a harness with a vault, the fixture key and a managed
//! project holding a copy of `ec-launch-fixture`.
//!
//! The helper is the person's program (`managed.register`, `.unregister`,
//! `.update_plan`, `.update`, with the passphrase from a file, run on a
//! pseudo-terminal of its own as `envcloak approve` is) and the client's
//! (the stand-in for `envcloak mcp-bridge --stdio --launch <id>`, which
//! M2-18 lands: hardened as the CLI is, it hands over its pipe ends and a
//! lifeline with the request). Its result is a JSON file; nothing it
//! writes is a value.
#![allow(dead_code, clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use envcloak_e2e::{Harness, quoted, sha256_hex, text};
use envcloak_testkit::{Canary, fresh_seed, labels};
use serde_json::{Value, json};

/// What the helper does: `register`, `unregister`, `plan`, `update` or
/// `request`.
pub const HELPER: &str = "EC_M27_HELPER";
/// The helper's input, a JSON file.
pub const HELPER_IN: &str = "EC_M27_IN";
/// Where the helper writes its result, a JSON file.
pub const HELPER_OUT: &str = "EC_M27_OUT";

/// The fixture key's label and variable.
pub const KEY: &str = "FIXTURE_KEY";

/// A Stripe test key, made at run time: no key-shaped literal is in the
/// source.
pub fn stripe_test_key() -> String {
    let tail: String = (0..2)
        .map(|_| format!("{:016x}", fresh_seed()))
        .collect::<String>();
    format!("{}_test_{tail}", concat!("s", "k"))
}

// ------------------------------------------------------------ the helper

fn write_json(path: &Path, v: &Value) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, v.to_string()).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

fn rpc_error(e: &envcloak_ipc::ClientError) -> Value {
    match e {
        envcloak_ipc::ClientError::Rpc(r) => json!({"error": r.kind.token(), "reason": r.reason}),
        other => json!({"error": format!("{other:?}")}),
    }
}

/// A call's answer as JSON, or its error.
macro_rules! shown {
    ($r:expr) => {
        match $r {
            Ok(v) => serde_json::to_value(v).unwrap(),
            Err(e) => rpc_error(&e),
        }
    };
}

fn passphrase(input: &Value) -> envcloak_core::SecretBytes {
    let path = input["passphrase_file"].as_str().unwrap();
    let mut v = std::fs::read(path).unwrap();
    while v.last() == Some(&b'\n') {
        v.pop();
    }
    envcloak_core::SecretBytes::from_vec(v)
}

fn connect() -> envcloak_ipc::Client {
    let paths = envcloak_ipc::RunPaths::for_user().unwrap();
    envcloak_ipc::Client::connect(&paths).unwrap()
}

/// The person's side: `managed.register`, `.unregister`, `.update_plan`
/// and `.update`.
fn helper_proof(action: &str, input: &Value) -> Value {
    use envcloak_ipc::proto::{LaunchDeclParams, ManagedRegisterParams, ManagedServerDecl};
    let mut c = connect();
    let changes: envcloak_policy::managed::LaunchChanges =
        serde_json::from_value(input["changes"].clone()).unwrap_or_default();
    match action {
        "register" => {
            let server = if let Some(origin) = input["origin"].as_str() {
                ManagedServerDecl::Bridge {
                    origin: origin.to_owned(),
                    header_names: serde_json::from_value(input["headers"].clone()).unwrap(),
                }
            } else {
                ManagedServerDecl::Stdio {
                    launch: LaunchDeclParams {
                        argv: serde_json::from_value(input["argv"].clone()).unwrap(),
                        cwd: input["cwd"].as_str().map(str::to_owned),
                        env: serde_json::from_value(input["env"].clone()).unwrap_or_default(),
                        path_env: input["path_env"].as_str().map(str::to_owned),
                    },
                }
            };
            let p = ManagedRegisterParams {
                name: input["name"].as_str().unwrap().to_owned(),
                manifest: input["manifest"].as_str().unwrap().to_owned(),
                server,
                passphrase: envcloak_ipc::WireSecret::new(passphrase(input)),
                claims: Vec::new(),
            };
            shown!(c.register_managed(&p))
        }
        "unregister" => {
            shown!(c.unregister_managed(input["id"].as_str().unwrap(), passphrase(input), &[]))
        }
        "plan" => shown!(c.plan_managed_update(input["launch"].as_str().unwrap(), &changes, &[])),
        "update" => shown!(c.update_managed(
            input["launch"].as_str().unwrap(),
            &changes,
            input["digest"].as_str().unwrap(),
            passphrase(input),
            &[],
        )),
        _ => json!({"error": "unknown action"}),
    }
}

/// Reads one line from `from` within `limit`: `None` when none came.
fn line_within(from: &mut BufReader<std::fs::File>, limit: Duration) -> Option<String> {
    let ready = !from.buffer().is_empty()
        || matches!(
            envcloak_sys::wait_readable(std::os::fd::AsFd::as_fd(from.get_ref()), limit),
            Ok(true)
        );
    if !ready {
        return None;
    }
    let mut got = String::new();
    match from.read_line(&mut got) {
        Ok(n) if n > 0 => Some(got),
        _ => None,
    }
}

/// Writes `lines` to the server one at a time, reading one line back for
/// each (`null` for none within 30 seconds).
fn ask(
    to: &mut std::fs::File,
    from: &mut BufReader<std::fs::File>,
    lines: &Value,
    replies: &mut Vec<Value>,
) {
    for line in lines.as_array().cloned().unwrap_or_default() {
        let sent = writeln!(to, "{}", line.as_str().unwrap()).and_then(|()| to.flush());
        if sent.is_err() {
            replies.push(Value::Null);
            continue;
        }
        replies.push(line_within(from, Duration::from_secs(30)).map_or(Value::Null, Value::from));
    }
}

/// The client's side (the stand-in for `mcp-bridge --stdio --launch`):
/// hardened as the CLI is, it asks for the launch (or the bridge) with its
/// pipe ends and a lifeline. When `started`, it writes `send`'s lines to
/// the server and reads one line back for each. Then, with
/// `progress_file` and `continue_file`, it says so and waits for the test
/// and sends `send_after`'s lines the same way; with `lifeline_only`, it
/// ends the lifeline and keeps its input open, and reports how long the
/// server took to end its output; otherwise it holds on `hold_ms` and
/// ends. `control` is held in memory to the end.
fn helper_request(input: &Value) -> Value {
    envcloak_sys::harden_process();
    let control = input["control"].as_str().map(str::to_owned);
    let (server_in, to_server) = envcloak_sys::pipe_cloexec().unwrap();
    let (from_server, server_out) = envcloak_sys::pipe_cloexec().unwrap();
    let (life_read, life_write) = envcloak_sys::pipe_cloexec().unwrap();
    // With `stderr`, the server's standard error too, read to its end once
    // the rest is done.
    let (from_errors, errors) = if input["stderr"].as_bool().unwrap_or(false) {
        let (r, w) = envcloak_sys::pipe_cloexec().unwrap();
        (Some(r), Some(w))
    } else {
        (None, None)
    };
    let fds = envcloak_ipc::ClientFds {
        stdin: server_in,
        stdout: server_out,
        stderr: errors,
        lifeline: life_read,
    };
    let p = envcloak_ipc::proto::RunRequestParams {
        manifest: input["manifest"].as_str().unwrap_or("").to_owned(),
        profile: input["profile"].as_str().map(str::to_owned),
        refs: serde_json::from_value(input["refs"].clone()).unwrap_or_default(),
        env_file: None,
        argv: vec!["mcp-bridge".to_owned()],
        claims: Vec::new(),
        launch: input["launch"].as_str().map(str::to_owned),
        bridge: input.get("origin").and_then(Value::as_str).map(|o| {
            envcloak_ipc::proto::BridgeDecl {
                origin: o.to_owned(),
                header_names: serde_json::from_value(input["headers"].clone()).unwrap(),
            }
        }),
        fds: Vec::new(),
    };
    let mut c = connect();
    let answer = c.run_request_with_fds(&p, &fds);
    drop(c);
    drop(fds);
    let answer = match answer {
        Ok(a) => a,
        Err(e) => return rpc_error(&e),
    };
    let decision = serde_json::to_value(&answer.decision).unwrap();
    let started = matches!(
        answer.decision,
        envcloak_ipc::view::DecisionView::Started {}
    );
    let mut out = json!({"decision": decision});
    if !started {
        return out;
    }
    let mut to = std::fs::File::from(to_server);
    let mut from = BufReader::new(std::fs::File::from(from_server));
    let mut replies = Vec::new();
    ask(&mut to, &mut from, &input["send"], &mut replies);
    // While the server runs: its parent (the runner) and the runner's
    // parent, from the kernel.
    if let Some(r) = replies
        .first()
        .and_then(Value::as_str)
        .and_then(|l| serde_json::from_str::<Value>(l.trim()).ok())
    {
        let runner = r["ppid"].as_i64().and_then(|p| i32::try_from(p).ok());
        out["runner_parent"] = json!(
            runner
                .and_then(|p| envcloak_sys::proc_info(p).ok())
                .map(|p| p.ppid)
        );
    }
    if let (Some(progress), Some(cont)) = (
        input["progress_file"].as_str(),
        input["continue_file"].as_str(),
    ) {
        write_json(Path::new(progress), &json!({"replies": replies}));
        let end = Instant::now() + Duration::from_secs(120);
        while !Path::new(cont).exists() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        ask(&mut to, &mut from, &input["send_after"], &mut replies);
    }
    if input["stall"].as_bool().unwrap_or(false) {
        // A client that stops reading: the server floods its output, and
        // the client ends its lifeline only, its output's reading end held
        // and never read. How long its runner takes to go.
        let runner = replies
            .first()
            .and_then(Value::as_str)
            .and_then(|l| serde_json::from_str::<Value>(l.trim()).ok())
            .and_then(|r| r["ppid"].as_i64())
            .and_then(|p| i32::try_from(p).ok());
        let _ = writeln!(to, "flood").and_then(|()| to.flush());
        std::thread::sleep(Duration::from_millis(500));
        let t = Instant::now();
        drop(life_write);
        // The daemon reaps its runner as soon as it exits.
        let gone = |pid: i32| envcloak_sys::proc_info(pid).is_err();
        out["runner_gone_ms"] = match runner {
            Some(pid) => {
                while !gone(pid) && t.elapsed() < Duration::from_secs(20) {
                    std::thread::sleep(Duration::from_millis(20));
                }
                if gone(pid) {
                    json!(u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX))
                } else {
                    Value::Null
                }
            }
            None => Value::Null,
        };
        out["replies"] = Value::from(replies);
        drop(to);
        drop(from);
        return out;
    }
    if input["lifeline_only"].as_bool().unwrap_or(false) {
        let t = Instant::now();
        drop(life_write);
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut rest = Vec::new();
            let _ = from.read_to_end(&mut rest);
            let _ = tx.send(());
        });
        out["output_ended_ms"] = match rx.recv_timeout(Duration::from_secs(15)) {
            Ok(()) => json!(u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)),
            Err(_) => Value::Null,
        };
        drop(to);
    } else {
        std::thread::sleep(Duration::from_millis(
            input["hold_ms"].as_u64().unwrap_or(0),
        ));
        drop(to);
        drop(life_write);
    }
    out["replies"] = Value::from(replies);
    if let Some(e) = from_errors {
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut all = Vec::new();
            let _ = std::fs::File::from(e).read_to_end(&mut all);
            let _ = tx.send(all);
        });
        out["stderr"] = rx
            .recv_timeout(Duration::from_secs(30))
            .map_or(Value::Null, |b| {
                Value::from(String::from_utf8_lossy(&b).into_owned())
            });
    }
    if let Some(c) = control {
        out["control_len"] = json!(std::hint::black_box(&c).len());
    }
    out
}

/// What a test binary's `helper` test runs: nothing, unless this binary
/// was started as a helper ([`HELPER`]); then the action, its result
/// written to [`HELPER_OUT`], and the exit.
pub fn helper_main() {
    let Some(action) = std::env::var_os(HELPER) else {
        return;
    };
    let action = action.to_string_lossy().into_owned();
    let input: Value = std::env::var_os(HELPER_IN)
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    let out = if action == "request" {
        helper_request(&input)
    } else {
        helper_proof(&action, &input)
    };
    write_json(Path::new(&std::env::var_os(HELPER_OUT).unwrap()), &out);
    std::process::exit(0);
}

// --------------------------------------------------------- the world

/// Whether this run uses `ENVCLOAK_E2E_BIN_DIR`'s binaries (CI's release
/// job), which hold no test hook. Only a test that stops the daemon at a
/// test barrier (`ENVCLOAK_TEST_PAUSE`) or makes a step fail
/// (`ENVCLOAK_TEST_FAIL`) asks this, and says it was skipped there; every
/// other managed test, the spike's precondition and its permanent controls
/// among them, runs on the shipped binaries too, reading only what a
/// release build shows (answers, the person's `pending` list, sweeps).
pub fn release_run(test: &str) -> bool {
    let release = std::env::var_os("ENVCLOAK_E2E_BIN_DIR").is_some();
    if release {
        eprintln!("{test}: skipped on the release binaries: it needs the test build's hooks");
    }
    release
}

/// A helper the person runs in the background ([`World::person_background`]).
pub struct Background {
    thread: std::thread::JoinHandle<(envcloak_e2e::Person, Option<i32>)>,
    output: PathBuf,
    what: String,
}

/// One test's world: the harness, the managed project, the fixture.
pub struct World {
    pub h: Harness,
    /// The managed project's directory, canonical.
    pub project: PathBuf,
    /// The fixture's copy in `project/bin`, canonical.
    pub fixture: PathBuf,
    /// Where the fixture writes its start marker.
    pub marker: PathBuf,
    n: usize,
}

/// The `ec-launch-fixture` built beside this test binary.
pub fn fixture_bin() -> PathBuf {
    envcloak_testkit::testkit_bin("ec-launch-fixture")
}

/// Another build of the fixture at `to`: the same program, another
/// identity (on macOS signed again with another identifier, on Linux with
/// bytes appended after the ELF image, which do not change what runs).
pub fn other_build(to: &Path) {
    std::fs::copy(fixture_bin(), to).unwrap();
    if cfg!(target_os = "macos") {
        let signed = std::process::Command::new("/usr/bin/codesign")
            .args(["-f", "-s", "-", "-i", "ec.launch.fixture.other"])
            .arg(to)
            .output()
            .unwrap();
        assert!(signed.status.success(), "{}", text(&signed));
    } else {
        let mut f = std::fs::OpenOptions::new().append(true).open(to).unwrap();
        f.write_all(b"another build").unwrap();
    }
}

impl World {
    /// A daemon (with `env`, and the test trace) with a vault, the fixture
    /// key added as `stripe/fixture`, and the managed project `fixture`,
    /// whose manifest binds it, with a copy of the fixture in `bin/`.
    pub fn new(env: &[(&str, &str)]) -> World {
        let mut env = env.to_vec();
        env.push(("ENVCLOAK_TEST_TRACE", "1"));
        World::with(Harness::start_with(&env))
    }

    /// As [`World::new`], with `envcloak` and `envcloakd` from `bins`.
    pub fn new_from(bins: PathBuf, env: &[(&str, &str)]) -> World {
        let mut env = env.to_vec();
        env.push(("ENVCLOAK_TEST_TRACE", "1"));
        World::with(Harness::start_from(bins, &env))
    }

    fn with(mut h: Harness) -> World {
        let home = h.home.home();
        let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
        let kit = h.files().join("kit");
        let created = h.human(
            &home,
            &[
                "vault",
                "create",
                "--passphrase-fd",
                "3",
                "--kit-fd",
                "4",
                "--kdf-memory",
                "64MiB",
            ],
            &[(3, &pass, true), (4, &kit, false)],
            &[],
        );
        assert_eq!(created.code, 0, "{}", created.all());
        let kit_text = std::fs::read_to_string(&kit).unwrap();
        h.add_canary(Canary::new(
            envcloak_e2e::RECOVERY_KIT,
            kit_text.trim_end().to_owned(),
        ));
        h.add_canary(Canary::new(KEY, stripe_test_key()));
        let file = h.secret_file(KEY, true);
        let cli = h.cli();
        let added = h.program(
            &cli,
            &["add", "stripe", "--slug", "stripe/fixture", "--stdin"],
            Some(&file),
        );
        assert!(added.status.success(), "{}", text(&added));
        let project = h.home.root().join("fixture");
        std::fs::create_dir_all(project.join("bin")).unwrap();
        std::fs::write(
            project.join("envcloak.toml"),
            format!("[project]\nname = \"fixture\"\n\n[env]\n{KEY} = \"stripe/fixture\"\n"),
        )
        .unwrap();
        let fixture = project.join("bin").join("ec-launch-fixture");
        std::fs::copy(fixture_bin(), &fixture).unwrap();
        let project = std::fs::canonicalize(project).unwrap();
        let fixture = std::fs::canonicalize(fixture).unwrap();
        let marker = h.files().join("fixture-ran");
        World {
            h,
            project,
            fixture,
            marker,
            n: 0,
        }
    }

    pub fn io_paths(&mut self) -> (PathBuf, PathBuf) {
        self.n += 1;
        let dir = self.h.files().to_path_buf();
        (
            dir.join(format!("m27-in-{}.json", self.n)),
            dir.join(format!("m27-out-{}.json", self.n)),
        )
    }

    /// The helper's argv: `env` setting its variables, then this binary.
    pub fn helper_argv(action: &str, input: &Path, output: &Path) -> Vec<String> {
        let me = std::env::current_exe().unwrap();
        vec![
            "/usr/bin/env".to_owned(),
            format!("{HELPER}={action}"),
            format!("{HELPER_IN}={}", input.display()),
            format!("{HELPER_OUT}={}", output.display()),
            me.to_str().unwrap().to_owned(),
            "--exact".to_owned(),
            "helper".to_owned(),
            "--nocapture".to_owned(),
            "--test-threads".to_owned(),
            "1".to_owned(),
        ]
    }

    /// The helper's result at `output`, swept.
    pub fn read_out(&mut self, output: &Path, what: &str) -> Value {
        let bytes = std::fs::read(output)
            .unwrap_or_else(|e| panic!("{what}: the helper wrote no result: {e}"));
        self.h.record(what, &bytes);
        self.h.assert_clean(what, &bytes);
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Waits up to `limit` for the helper's result at `output`.
    pub fn wait_out(&mut self, output: &Path, limit: Duration, what: &str) -> Value {
        assert!(appears(output, limit), "{what}: no result within {limit:?}");
        self.read_out(output, what)
    }

    /// The person runs the helper's `action` (with the passphrase) on a
    /// terminal of their own.
    pub fn person(&mut self, action: &str, mut input: Value) -> Value {
        let pass = self.h.secret_file(labels::VAULT_PASSPHRASE, true);
        input["passphrase_file"] = json!(pass.to_str().unwrap());
        let (i, o) = self.io_paths();
        std::fs::write(&i, input.to_string()).unwrap();
        let argv = Self::helper_argv(action, &i, &o);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let home = self.h.home.home();
        let ran = self.h.human_argv(&home, &argv, &[], &[]);
        assert_eq!(ran.code, 0, "{}", ran.all());
        self.read_out(&o, &format!("the person's {action}"))
    }

    /// As [`World::person`], on a thread of its own, returning at once:
    /// [`World::person_done`] takes its result.
    pub fn person_background(&mut self, action: &str, mut input: Value) -> Background {
        let pass = self.h.secret_file(labels::VAULT_PASSPHRASE, true);
        input["passphrase_file"] = json!(pass.to_str().unwrap());
        let (i, o) = self.io_paths();
        std::fs::write(&i, input.to_string()).unwrap();
        let argv = Self::helper_argv(action, &i, &o);
        let person = self.h.person();
        let home = self.h.home.home();
        let thread = std::thread::spawn(move || {
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            let ran = person.run_argv(&home, &argv, &[], Duration::from_secs(120));
            (person, ran.map(|r| r.code))
        });
        Background {
            thread,
            output: o,
            what: format!("the person's {action}"),
        }
    }

    /// The result of a [`World::person_background`] run, swept.
    pub fn person_done(&mut self, b: Background) -> Value {
        let (person, code) = b.thread.join().unwrap();
        self.h.keep_person(&person);
        assert_eq!(code, Some(0), "{} did not finish", b.what);
        self.read_out(&b.output, &b.what)
    }

    /// The agent runs the helper's `action`, in its home directory (not
    /// the managed project's).
    pub fn agent(&mut self, action: &str, input: &Value) -> Value {
        let (i, o) = self.io_paths();
        std::fs::write(&i, input.to_string()).unwrap();
        let line = Self::shell_line(action, &i, &o);
        let cwd = self.h.home.home();
        let ran = self.h.agent_line(&cwd, &line);
        assert!(ran.status.success(), "{}", text(&ran));
        self.read_out(&o, &format!("the agent's {action}"))
    }

    /// The test itself runs the helper's `action`: no terminal and no agent
    /// in its ancestry.
    pub fn no_terminal(&mut self, action: &str, input: &Value) -> Value {
        let (i, o) = self.io_paths();
        std::fs::write(&i, input.to_string()).unwrap();
        let argv = Self::helper_argv(action, &i, &o);
        let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
        let ran = self.h.program(Path::new(&argv[0]), &args, None);
        assert!(ran.status.success(), "{}", text(&ran));
        self.read_out(&o, &format!("{action} without a terminal"))
    }

    /// As [`World::agent`], started in the background: the result's path.
    pub fn agent_background(&mut self, action: &str, input: &Value) -> PathBuf {
        let (i, o) = self.io_paths();
        std::fs::write(&i, input.to_string()).unwrap();
        let line = Self::shell_line(action, &i, &o);
        let cwd = self.h.home.home();
        self.h.agent_spawn(&cwd, &line);
        o
    }

    fn shell_line(action: &str, i: &Path, o: &Path) -> String {
        let argv = Self::helper_argv(action, i, o);
        let line: Vec<String> = argv.iter().map(|a| quoted(a)).collect();
        line.join(" ")
    }

    /// Registers `claude-code/fixture` for the managed project with the
    /// fields of `decl`, and returns the answer.
    pub fn register(&mut self, decl: Value) -> Value {
        let mut input = json!({
            "name": "claude-code/fixture",
            "manifest": self.project.join("envcloak.toml").to_str().unwrap(),
        });
        for (k, v) in decl.as_object().unwrap() {
            input[k] = v.clone();
        }
        self.person("register", input)
    }

    /// The fixture's argv run as `program`, with its start marker,
    /// reporting the key's digest and whether code-selecting variables
    /// reached it.
    pub fn fixture_argv_for(&self, program: &str) -> Value {
        json!([
            program,
            "--marker",
            self.marker.to_str().unwrap(),
            "--var",
            KEY,
            "--var",
            "LD_PRELOAD",
            "--var",
            "NODE_OPTIONS",
            "--var",
            "PYTHONPATH",
            "--var",
            "DYLD_LIBRARY_PATH"
        ])
    }

    pub fn fixture_argv(&self) -> Value {
        self.fixture_argv_for(self.fixture.to_str().unwrap())
    }

    /// Registers the fixture by its path: the launch id and the answer.
    pub fn register_fixture(&mut self) -> (String, Value) {
        let argv = self.fixture_argv();
        let reg = self.register(json!({ "argv": argv }));
        let launch = reg["launch"]
            .as_str()
            .unwrap_or_else(|| panic!("not registered: {reg}"))
            .to_owned();
        (launch, reg)
    }

    /// The agent's client asks for `launch`, sending `report` once started.
    pub fn request(&mut self, launch: &str) -> Value {
        self.agent(
            "request",
            &json!({"launch": launch, "send": ["report"], "hold_ms": 0}),
        )
    }

    /// The person approves request `id` for the session.
    pub fn approve(&mut self, id: &str) {
        let typed = format!("{}\r", self.h.canary(labels::VAULT_PASSPHRASE).as_str());
        let project = self.project.clone();
        let approved = self.h.human(
            &project,
            &["approve", id],
            &[],
            &[("Vault passphrase to approve this: ", &typed)],
        );
        assert_eq!(approved.code, 0, "{}", approved.all());
    }

    /// Registers the fixture, has the agent's request approved, and checks
    /// the next one starts the record's image (the positive control): the
    /// launch id, the registration and the started answer.
    pub fn launched(&mut self) -> (String, Value, Value) {
        let (launch, reg) = self.register_fixture();
        let first = self.request(&launch);
        self.approve(&pending_id(&first));
        let answer = self.request(&launch);
        assert!(started(&answer), "{answer}");
        assert_eq!(
            reported_identity(&report(&answer)),
            receipt_identity(&reg),
            "{answer}"
        );
        (launch, reg, answer)
    }

    /// The SHA-256 of the fixture key, as the fixture reports it.
    pub fn key_digest(&self) -> String {
        sha256_hex(self.h.value(KEY))
    }

    /// The daemons' logs, as text.
    pub fn logs(&self) -> String {
        self.h
            .daemon_logs()
            .iter()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Whether the daemon is the test build, whose test trace counts what
    /// it released ([`World::released`]).
    pub fn traced(&self) -> bool {
        self.h.test_build()
    }

    /// Asserts the daemons released values to a client `client` times and
    /// to a runner `runner` times, where the test build's trace counts
    /// them; a release build's daemon keeps no such count, and its tests
    /// rest on the sweeps alone.
    pub fn assert_released(&self, client: usize, runner: usize, when: &str) {
        if self.traced() {
            assert_eq!(self.released(), (client, runner), "{when}");
        }
    }

    /// How often the daemons' logs say values went to a client, and to a
    /// runner.
    pub fn released(&self) -> (usize, usize) {
        let logs = self.logs();
        (
            logs.matches("run.request released values to the client")
                .count(),
            logs.matches("run.request released values to a runner")
                .count(),
        )
    }

    /// How many requests were left pending: on the test build, as the
    /// daemons' audit trace says (every one ever made); on a release
    /// build, as the person's `envcloak pending --json` lists them now.
    /// Either way, a request that made none leaves it unchanged.
    pub fn pending_count(&mut self) -> usize {
        if self.traced() {
            return self.logs().matches("decision=pending").count();
        }
        let home = self.h.home.home();
        let listed = self.h.human(&home, &["pending", "--json"], &[], &[]);
        assert_eq!(listed.code, 0, "{}", listed.all());
        let listed: Value = serde_json::from_str(&listed.out()).unwrap();
        listed["requests"].as_array().map_or(0, Vec::len)
    }

    /// Waits for the test build's trace to show `text`; a release build
    /// has no trace, and the caller's other checks stand alone there.
    pub fn expect_trace(&mut self, text: &str) {
        if self.traced() {
            self.h.expect_log(text, Duration::from_secs(10));
        }
    }
}

/// The pending request id in a decision.
pub fn pending_id(answer: &Value) -> String {
    (answer["decision"]["decision"] == "pending")
        .then(|| answer["decision"]["request"].as_str())
        .flatten()
        .unwrap_or_else(|| panic!("not pending: {answer}"))
        .to_owned()
}

pub fn started(answer: &Value) -> bool {
    answer["decision"]["decision"] == "started"
}

/// The error kind of a refused request or call.
pub fn error_of(answer: &Value) -> &str {
    answer["error"].as_str().unwrap_or("")
}

/// Reply `n` of a request's answer: the fixture's report.
pub fn report_at(answer: &Value, n: usize) -> Value {
    let line = answer["replies"][n]
        .as_str()
        .unwrap_or_else(|| panic!("no reply {n}: {answer}"));
    serde_json::from_str(line.trim()).unwrap_or_else(|_| panic!("not a report: {line:?}"))
}

pub fn report(answer: &Value) -> Value {
    report_at(answer, 0)
}

/// The executable's identity as a registration's receipt shows it.
pub fn receipt_identity(registered: &Value) -> String {
    registered["receipt"]["identity"]
        .as_str()
        .unwrap_or_else(|| panic!("no identity: {registered}"))
        .to_owned()
}

/// The identity the fixture reports, written as a receipt writes it.
pub fn reported_identity(r: &Value) -> String {
    match (r["exe_sha256"].as_str(), r["cdhash"].as_str()) {
        (Some(h), _) if cfg!(target_os = "linux") => format!("sha256:{h}"),
        (_, Some(c)) => format!("cdhash:{c}"),
        _ => panic!("the fixture reported no identity: {r}"),
    }
}

/// `path`'s identity as an independent oracle reads it: the SHA-256 of
/// its bytes on Linux, the code directory hash `codesign` prints on macOS.
pub fn file_identity(path: &Path) -> String {
    if cfg!(target_os = "macos") {
        let out = std::process::Command::new("/usr/bin/codesign")
            .arg("-dvvv")
            .arg(path)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stderr).into_owned();
        let h = text
            .lines()
            .find_map(|l| l.strip_prefix("CDHash="))
            .unwrap_or_else(|| panic!("no CDHash for {}: {text}", path.display()));
        format!("cdhash:{h}")
    } else {
        format!("sha256:{}", sha256_hex(&std::fs::read(path).unwrap()))
    }
}

/// Waits up to `limit` for `path` to exist.
pub fn appears(path: &Path, limit: Duration) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    path.exists()
}
