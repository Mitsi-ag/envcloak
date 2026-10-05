//! The daemon-started runner (SPEC §6.6; M2 plan D-34, D-36, CR-1; task
//! M2-27; gate 39), end to end through the built `envcloak` and
//! `envcloakd`: a managed server's key goes only to the process the
//! daemon starts itself, from its own image, never to the client that
//! asked, whatever that client is; the runner outlives the daemon; and a
//! runner the daemon did not start receives nothing.
//!
//! The person's and the client's programs are this test binary run again
//! as a helper (`managed_common`); the foreign client is a Python program
//! with no EnvCloak code. Everything any process printed or wrote for the
//! test, every daemon log and the whole home are swept for the fixture
//! key in every encoding.
#![allow(clippy::unwrap_used)]

mod managed_common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use envcloak_e2e::{python3, sha256_hex, text};
use managed_common::{
    KEY, World, appears, error_of, helper_main, pending_id, receipt_identity, report, report_at,
    reported_identity, started,
};
use serde_json::{Value, json};

/// Runs only as the helper (`managed_common`).
#[test]
fn helper() {
    helper_main();
}

/// Gate 39's positive control and D-36: the registered launch, asked by
/// an agent's hardened client with its pipe ends, is pending until the
/// person approves; then the daemon answers `started` and its runner,
/// started from the daemon's own image, starts the registered fixture:
/// the fixture's image is the record's (its digest), it runs in the
/// registered directory though the client runs in another, and it has
/// the key (its digest); the fixture's parent is the runner and the
/// runner's the daemon. The client got no value: the daemon released
/// values to a runner once and to a client never, and every output, log
/// and file is clean.
///
/// Mutation checked: the values returned to the requesting client instead
/// of starting the runner (the previous design): the client-release
/// counter is 1 and the runner's 0, and this fails.
#[test]
fn a_registered_launch_runs_the_record_and_gives_the_client_nothing() {
    if managed_common::release_run(
        "a_registered_launch_runs_the_record_and_gives_the_client_nothing",
    ) {
        return;
    }
    let mut w = World::new(&[]);
    let (launch, reg) = w.register_fixture();
    assert_eq!(reg["revision"], 1, "{reg}");
    assert_eq!(reg["receipt"]["class"], "native", "{reg}");
    assert_eq!(reg["receipt"]["strength"], "bound", "{reg}");
    assert_eq!(
        receipt_identity(&reg),
        managed_common::file_identity(&w.fixture),
        "the receipt's identity is not the oracle's"
    );
    let first = w.request(&launch);
    let id = pending_id(&first);
    assert_eq!(w.released(), (0, 0));
    w.approve(&id);
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    let r = report(&answer);
    assert_eq!(reported_identity(&r), receipt_identity(&reg), "{r}");
    assert_eq!(r["vars"][KEY], w.key_digest(), "{r}");
    assert_eq!(
        r["cwd_sha256"],
        sha256_hex(w.project.as_os_str().as_encoded_bytes()),
        "{r}"
    );
    assert_eq!(answer["runner_parent"], w.h.daemon.pid(), "{answer}");
    assert_eq!(w.released(), (0, 1));
    w.h.assert_swept("after the launch");
}

/// A client with no EnvCloak code: Python, connecting to the socket and
/// sending `run.request` with three descriptors (`socket.send_fds`). It
/// prints what it received as JSON: the daemon's answer and the server's
/// reply to `report`, both as text.
const FOREIGN: &str = r#"import json, os, select, socket, struct, sys
sock_path, launch, out = sys.argv[1:4]
r0, w0 = os.pipe()
r1, w1 = os.pipe()
rl, wl = os.pipe()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
req = {"jsonrpc": "2.0", "id": 1, "method": "run.request",
       "params": {"manifest": "", "argv": ["foreign"], "launch": launch,
                  "fds": ["stdin", "stdout", "lifeline"]}}
body = json.dumps(req).encode()
socket.send_fds(s, [struct.pack(">I", len(body))], [r0, w1, rl])
s.sendall(body)
def recv(n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            break
        b += c
    return b
n = struct.unpack(">I", recv(4))[0]
resp = recv(n)
os.close(r0); os.close(w1); os.close(rl)
reply = b""
if b'"started"' in resp:
    os.write(w0, b"report\n")
    while not reply.endswith(b"\n"):
        r, _, _ = select.select([r1], [], [], 30)
        if not r:
            break
        c = os.read(r1, 4096)
        if not c:
            break
        reply += c
os.close(w0); os.close(wl)
json.dump({"response": resp.decode("utf-8", "replace"), "reply": reply.decode("utf-8", "replace")}, open(out, "w"))
"#;

/// Gate 39's negative control (CR-1, D-36): a foreign client with no
/// EnvCloak code names the registered launch over the socket with pipes
/// of its own. Pending until the person approves its request; then it
/// gets `started` and the fixture's traffic, which shows the fixture got
/// the key, and no value byte: everything it received is swept for the
/// key in every encoding, and the daemon released values to a client
/// never.
///
/// Mutation checked: the values returned to the requesting client instead
/// of starting the runner: the answer the foreign client received holds
/// the key (base64), the sweep finds it, and this fails.
#[test]
fn a_foreign_client_gets_started_and_no_value() {
    if managed_common::release_run("a_foreign_client_gets_started_and_no_value") {
        return;
    }
    let mut w = World::new(&[]);
    let (launch, _) = w.register_fixture();
    let socket = envcloak_testkit::daemon_socket(&w.h.home);
    let ask = |w: &mut World| -> Value {
        let (_, out) = w.io_paths();
        let line = format!(
            "{} -c {} {} {} {}",
            envcloak_e2e::quoted(python3().to_str().unwrap()),
            envcloak_e2e::quoted(FOREIGN),
            envcloak_e2e::quoted(socket.to_str().unwrap()),
            launch,
            envcloak_e2e::quoted(out.to_str().unwrap())
        );
        let home = w.h.home.home();
        let ran = w.h.agent_line(&home, &line);
        assert!(ran.status.success(), "{}", text(&ran));
        w.read_out(&out, "the foreign client's")
    };
    let first = ask(&mut w);
    let response: Value = serde_json::from_str(first["response"].as_str().unwrap()).unwrap();
    let id = response["result"]["decision"]["request"]
        .as_str()
        .unwrap_or_else(|| panic!("not pending: {first}"))
        .to_owned();
    w.approve(&id);
    let second = ask(&mut w);
    let response: Value = serde_json::from_str(second["response"].as_str().unwrap()).unwrap();
    assert_eq!(
        response["result"]["decision"]["decision"], "started",
        "{second}"
    );
    let r: Value = serde_json::from_str(second["reply"].as_str().unwrap().trim()).unwrap();
    assert_eq!(r["vars"][KEY], w.key_digest(), "{r}");
    assert_eq!(w.released(), (0, 1));
    w.h.assert_swept("after the foreign client");
}

/// The test library the injected-library control loads into the client
/// (`LD_PRELOAD` on Linux, `DYLD_INSERT_LIBRARIES` on macOS): at exit it
/// writes every readable and writable region of the process's memory (its
/// heap, stacks and data: where anything it received at run time is) to
/// the file `EC_M27_DUMP` names.
const DUMPER: &str = r#"#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif
__attribute__((destructor)) static void ec_dump(void) {
    const char *out = getenv("EC_M27_DUMP");
    if (!out) return;
    int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
#ifdef __APPLE__
    mach_vm_address_t addr = 0;
    for (;;) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        if (mach_vm_region(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &count, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) {
            for (mach_vm_size_t off = 0; off < size; off += 65536) {
                mach_vm_size_t n = size - off < 65536 ? size - off : 65536;
                if (write(fd, (const void *)(addr + off), n) < 0) break;
            }
        }
        addr += size;
    }
#else
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[1024];
    while (maps && fgets(line, sizeof line, maps)) {
        unsigned long a, b;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s", &a, &b, perms) != 3) continue;
        if (perms[0] != 'r' || perms[1] != 'w' || strstr(line, "[vvar")) continue;
        for (unsigned long p = a; p < b; p += 65536) {
            unsigned long n = b - p < 65536 ? b - p : 65536;
            if (write(fd, (const void *)p, n) < 0) break;
        }
    }
    if (maps) fclose(maps);
#endif
    close(fd);
}
"#;

/// Builds the dumper with the system's C compiler.
fn dumper(dir: &Path) -> PathBuf {
    let src = dir.join("ec-dump.c");
    std::fs::write(&src, DUMPER).unwrap();
    let lib = dir.join(if cfg!(target_os = "macos") {
        "ec-dump.dylib"
    } else {
        "ec-dump.so"
    });
    let shared = if cfg!(target_os = "macos") {
        "-dynamiclib"
    } else {
        "-shared"
    };
    let built = std::process::Command::new("cc")
        .args([shared, "-fPIC", "-O0", "-o"])
        .arg(&lib)
        .arg(&src)
        .output()
        .unwrap_or_else(|e| panic!("cc is needed for the injected-library control: {e}"));
    assert!(built.status.success(), "{}", text(&built));
    lib
}

/// Gate 39's injected-library control (CR-1): the client, started with
/// the test library loaded into it (`LD_PRELOAD` on Linux,
/// `DYLD_INSERT_LIBRARIES` on macOS), which writes all of its readable
/// memory to a file at exit, asks for the launch and is answered
/// `started`; the dump holds the client's own positive control (a marker
/// it kept in memory) and no encoding of the key.
///
/// Mutation checked: the runner writing the server's environment to its
/// client's output before starting the server: the dump holds the key, and
/// this fails at its sweep (checked before the answer is).
#[test]
fn an_injected_library_finds_no_value_in_the_client() {
    if managed_common::release_run("an_injected_library_finds_no_value_in_the_client") {
        return;
    }
    let mut w = World::new(&[]);
    let lib = dumper(w.h.files());
    let (launch, _) = w.register_fixture();
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let control = format!("ec-m27-control-{:016x}", envcloak_testkit::fresh_seed());
    let dump = w.h.files().join("client.dump");
    let (input, output) = w.io_paths();
    std::fs::write(
        &input,
        json!({"launch": launch, "send": ["report"], "control": control}).to_string(),
    )
    .unwrap();
    // Set by the shell for the client itself: a system program in between
    // (`env`) would have the loader drop the variable on macOS.
    let preload = if cfg!(target_os = "macos") {
        "DYLD_INSERT_LIBRARIES"
    } else {
        "LD_PRELOAD"
    };
    let me = std::env::current_exe().unwrap();
    let q = |p: &Path| envcloak_e2e::quoted(p.to_str().unwrap());
    let line = format!(
        "{preload}={} EC_M27_DUMP={} {}=request {}={} {}={} {} --exact helper --nocapture \
         --test-threads 1",
        q(&lib),
        q(&dump),
        managed_common::HELPER,
        managed_common::HELPER_IN,
        q(&input),
        managed_common::HELPER_OUT,
        q(&output),
        q(&me)
    );
    let home = w.h.home.home();
    let ran = w.h.agent_line(&home, &line);
    assert!(ran.status.success(), "{}", text(&ran));
    // The dump first: what the client held, whatever it was answered.
    let bytes = std::fs::read(&dump).unwrap();
    let needle = control.as_bytes();
    let held = bytes
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == needle[0])
        .any(|(i, _)| bytes.get(i..i + needle.len()) == Some(needle));
    assert!(
        held,
        "the dump does not hold the client's own control ({} bytes)",
        bytes.len()
    );
    w.h.assert_clean("the client's memory", &bytes);
    let answer = w.read_out(&output, "the injected client's");
    assert!(started(&answer), "{answer}");
    assert_eq!(report(&answer)["vars"][KEY], w.key_digest());
    w.h.assert_swept("after the injected client");
}

/// D-36: the runner and the server outlive `kill -9` of the daemon and a
/// daemon restart (two, one after a kill, one after a SIGTERM); the new
/// daemons hold no handle to them and signal nothing: the same fixture
/// process answers the client after both.
///
/// Mutation checked: the runner given `PR_SET_PDEATHSIG` (Linux): the
/// runner dies with the daemon, the server's input ends, and the second
/// report never comes.
#[test]
fn the_runner_outlives_the_daemon() {
    if managed_common::release_run("the_runner_outlives_the_daemon") {
        return;
    }
    let mut w = World::new(&[]);
    let (launch, reg) = w.register_fixture();
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let progress = w.h.files().join("progress.json");
    let cont = w.h.files().join("continue");
    let out = w.agent_background(
        "request",
        &json!({
            "launch": launch,
            "send": ["report"],
            "progress_file": progress.to_str().unwrap(),
            "continue_file": cont.to_str().unwrap(),
            "send_after": ["report"],
        }),
    );
    let progressed = w.wait_out(&progress, Duration::from_secs(60), "the first report");
    let before: Value =
        serde_json::from_str(progressed["replies"][0].as_str().unwrap().trim()).unwrap();
    assert_eq!(reported_identity(&before), receipt_identity(&reg));
    // kill -9, then a new daemon; then a stop and a start.
    w.h.daemon.signal("-KILL");
    assert!(w.h.daemon.wait_exit(Duration::from_secs(30)).is_some());
    w.h.start_daemon(&[]);
    let _ = w.h.stop_daemon();
    w.h.start_daemon(&[]);
    std::thread::sleep(Duration::from_millis(500));
    std::fs::write(&cont, b"go").unwrap();
    let answer = w.wait_out(&out, Duration::from_secs(60), "the client");
    let after = report_at(&answer, 1);
    assert_eq!(after["pid"], before["pid"], "{answer}");
    assert_eq!(after["vars"][KEY], w.key_digest());
    w.h.assert_swept("after the restarts");
}

/// D-34, D-36: the client gone (its lifeline's end of file, its input
/// still open) stops the server through the runner's owned handle within
/// 5 seconds.
///
/// Mutation checked: the runner's lifeline watcher never reporting the
/// end: the server's output stays open and this fails.
#[test]
fn the_lifeline_ending_stops_the_server() {
    if managed_common::release_run("the_lifeline_ending_stops_the_server") {
        return;
    }
    let mut w = World::new(&[]);
    let (launch, _) = w.register_fixture();
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.agent(
        "request",
        &json!({"launch": launch, "send": ["report"], "lifeline_only": true}),
    );
    assert!(started(&answer), "{answer}");
    let ms = answer["output_ended_ms"]
        .as_u64()
        .unwrap_or_else(|| panic!("the server did not stop: {answer}"));
    assert!(ms <= 6000, "{ms} ms");
}

/// D-34, D-36: the client killed (SIGKILL, by the shell that started it)
/// takes its lifeline and its end of the server's input with it, and the
/// runner stops the server through its owned handle within 5 seconds: the
/// server's process, a child of the runner until then (the positive
/// control), is gone. The server does not end with its input (it lingers
/// 30 seconds), so only the runner's stop ends it in time.
///
/// Mutation checked: the runner ignoring the client's endings (its lifeline
/// and input), stopping the server only when it exits by itself: the
/// server is still there after 8 seconds, and this fails.
#[test]
fn the_client_killed_stops_the_server() {
    if managed_common::release_run("the_client_killed_stops_the_server") {
        return;
    }
    let mut w = World::new(&[]);
    let mut argv = w.fixture_argv();
    argv.as_array_mut()
        .unwrap()
        .extend([json!("--linger"), json!("30")]);
    let reg = w.register(json!({ "argv": argv }));
    let launch = reg["launch"].as_str().unwrap().to_owned();
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let progress = w.h.files().join("progress.json");
    let never = w.h.files().join("never");
    let _ = w.agent_background(
        "request",
        &json!({
            "launch": launch,
            "send": ["report"],
            "progress_file": progress.to_str().unwrap(),
            "continue_file": never.to_str().unwrap(),
        }),
    );
    let progressed = w.wait_out(&progress, Duration::from_secs(60), "the first report");
    let r: Value = serde_json::from_str(progressed["replies"][0].as_str().unwrap().trim()).unwrap();
    let server = i32::try_from(r["pid"].as_i64().unwrap()).unwrap();
    let runner = r["ppid"].as_i64().unwrap();
    let alive = || envcloak_sys::proc_info(server).is_ok_and(|p| i64::from(p.ppid) == runner);
    assert!(alive(), "the server is not running under its runner: {r}");
    let t = std::time::Instant::now();
    w.h.agent_kill_last();
    while alive() {
        assert!(
            t.elapsed() < Duration::from_secs(8),
            "the server outlived its client"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let ms = t.elapsed().as_millis();
    assert!(ms <= 6000, "{ms} ms");
}

/// A fake daemon's channel: Python makes a socket pair, puts one end at
/// descriptor 3 (and a lifeline at 4, the project directory at 6) and
/// starts `envcloak run --launch <id>` itself, writing a well-formed
/// `Release` (a fake value, the fixture's launch) on its end first.
const NOT_THE_DAEMON: &str = r#"import base64, json, os, socket, struct, subprocess, sys
cli, launch, fixture, marker, cwd, value = sys.argv[1:7]
a, b = socket.socketpair()
rl, wl = os.pipe()
d = os.open(cwd, os.O_RDONLY)
release = {"Release": {"bindings": [{"env_name": "FIXTURE_KEY", "slug": "stripe/fixture",
    "allow_short": False, "value": base64.b64encode(value.encode()).decode()}],
    "to": {"runner": {"launch": launch, "spec": {"argv": [fixture, "--marker", marker],
    "path_env": "/usr/bin:/bin", "vars": [], "executable": fixture,
    "exec": {"path": {"confirm": False}}}}}}}
body = json.dumps(release).encode()
a.sendall(struct.pack(">I", len(body)) + body)
def fds():
    os.dup2(b.fileno(), 3)
    os.dup2(rl, 4)
    os.dup2(d, 6)
p = subprocess.run([cli, "run", "--launch", launch], preexec_fn=fds, pass_fds=(3, 4, 6),
    stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
sys.stdout.write(json.dumps({"code": p.returncode, "stderr": p.stderr.decode("utf-8", "replace")}))
"#;

/// D-36: `envcloak run --launch <id>` started by a test program instead of
/// the daemon, with a channel at descriptor 3 that holds a well-formed
/// release, exits 125 `not_started_by_daemon` and starts nothing (the
/// fixture's start marker never appears).
///
/// Mutation checked: the runner's started-by-daemon check accepting any
/// channel: it reads the fake release and starts the fixture, whose
/// marker appears, and this fails.
#[test]
fn a_runner_not_started_by_the_daemon_receives_nothing() {
    if managed_common::release_run("a_runner_not_started_by_the_daemon_receives_nothing") {
        return;
    }
    let mut w = World::new(&[]);
    let (launch, _) = w.register_fixture();
    let value = format!("ec-not-a-key-{:016x}", envcloak_testkit::fresh_seed());
    w.h.add_needle(
        "the fake release's value".into(),
        value.clone().into_bytes(),
    );
    let py = python3();
    let cli = w.h.cli();
    let out = w.h.program(
        &py,
        &[
            "-c",
            NOT_THE_DAEMON,
            cli.to_str().unwrap(),
            &launch,
            w.fixture.to_str().unwrap(),
            w.marker.to_str().unwrap(),
            w.project.to_str().unwrap(),
            &value,
        ],
        None,
    );
    assert!(out.status.success(), "{}", text(&out));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["code"], 125, "{r}");
    assert!(
        r["stderr"]
            .as_str()
            .unwrap()
            .starts_with("envcloak: not_started_by_daemon: "),
        "{r}"
    );
    assert!(
        !appears(&w.marker, Duration::from_secs(2)),
        "the fixture started"
    );
}

/// `runner_unavailable` with nothing released (D-36): the daemon unable to
/// start its runner answers so after the approval, and the fixture never
/// starts.
///
/// Mutation checked: the runner's failed start answered `started` (the
/// error dropped): this fails.
#[test]
fn a_runner_that_cannot_start_releases_nothing() {
    if managed_common::release_run("a_runner_that_cannot_start_releases_nothing") {
        return;
    }
    let mut w = World::new(&[("ENVCLOAK_TEST_FAIL", "launch.runner")]);
    let (launch, _) = w.register_fixture();
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.request(&launch);
    assert_eq!(error_of(&answer), "runner_unavailable", "{answer}");
    assert_eq!(w.released(), (0, 0));
    assert!(!w.marker.exists());
}

/// Linux (D-33, D-36): a sealed copy the system refuses (the executable
/// memory file refused) is `runner_unavailable` before any pending
/// request, never the file instead: nothing is released and the fixture
/// never starts.
///
/// Mutation checked: a refused sealed copy falling back to the checked
/// descriptor: the request is pending, and this fails.
#[test]
fn a_refused_sealed_copy_never_falls_back_to_the_file() {
    if managed_common::release_run("a_refused_sealed_copy_never_falls_back_to_the_file") {
        return;
    }
    if !cfg!(target_os = "linux") {
        eprintln!("a_refused_sealed_copy_never_falls_back_to_the_file: Linux only");
        return;
    }
    let mut w = World::new(&[("ENVCLOAK_TEST_FAIL", "launch.memfd")]);
    let (launch, _) = w.register_fixture();
    let pending = w.pending_count();
    let answer = w.request(&launch);
    assert_eq!(error_of(&answer), "runner_unavailable", "{answer}");
    assert_eq!(w.pending_count(), pending, "a pending request exists");
    assert_eq!(w.released(), (0, 0));
    assert!(!w.marker.exists());
}

/// No fallback (D-33): the runner's start of the server failing (as a
/// refused `execveat` of the sealed copy would) starts nothing else: the
/// fixture never ran.
///
/// Mutation checked: a failed start retried from the registered path: the
/// fixture's start marker appears, and this fails.
#[test]
fn a_failed_start_is_not_retried_from_the_file() {
    if managed_common::release_run("a_failed_start_is_not_retried_from_the_file") {
        return;
    }
    let mut w = World::new(&[("ENVCLOAK_TEST_FAIL", "launch.server_exec")]);
    let (launch, _) = w.register_fixture();
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.request(&launch);
    // On Linux the client was answered `started` before the runner tried;
    // on macOS the daemon waits for the runner's `ConfirmSpawn`, which a
    // failed start never sends: `runner_unavailable`.
    if started(&answer) {
        assert!(answer["replies"][0].is_null(), "{answer}");
    } else {
        assert_eq!(error_of(&answer), "runner_unavailable", "{answer}");
    }
    assert!(
        !appears(&w.marker, Duration::from_secs(2)),
        "the fixture ran"
    );
}

/// Copies of `envcloak` and `envcloakd` in a directory of their own, so a
/// test can replace the `envcloak` the daemon takes as its anchor.
fn own_bins(dir: &Path) -> PathBuf {
    let bins = dir.join("bin");
    std::fs::create_dir_all(&bins).unwrap();
    let from = envcloak_e2e::bin_dir();
    for name in ["envcloak", "envcloakd"] {
        std::fs::copy(from.join(name), bins.join(name)).unwrap();
    }
    bins
}

/// Replaces `path` (renamed over) with a shell script that writes
/// `marker`: no EnvCloak runner.
fn replace_with_script(path: &Path, marker: &Path) {
    let tmp = path.with_extension("new");
    envcloak_e2e::write_script(
        &tmp,
        &format!(
            "#!/bin/sh\necho ran > {}\n",
            envcloak_e2e::quoted(marker.to_str().unwrap())
        ),
    );
    std::fs::rename(&tmp, path).unwrap();
}

/// D-36's anchor: the `envcloak` beside `envcloakd` replaced after the
/// daemon started. On Linux the daemon still starts the image it sealed
/// at start (the launch succeeds and the replacement never runs); on
/// macOS a replacement whose code directory hash is not the anchor's is
/// refused before it runs (`runner_unavailable`, nothing released, the
/// replacement never runs). A new daemon takes the new image: another
/// build of `envcloak` put in place, the daemon restarted, the launch
/// succeeds.
///
/// Mutation checked: the runner started from the installed file instead
/// of the image taken at start (Linux): the replacement runs, its marker
/// appears, and this fails.
#[test]
fn the_anchor_is_the_image_taken_at_start() {
    if managed_common::release_run("the_anchor_is_the_image_taken_at_start") {
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("eca")
        .tempdir_in("/tmp")
        .unwrap();
    let bins = own_bins(tmp.path());
    let mut w = World::new_from(bins.clone(), &[]);
    let (launch, _) = w.register_fixture();
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let wrong = w.h.files().join("wrong-runner-ran");
    replace_with_script(&bins.join("envcloak"), &wrong);
    let answer = w.request(&launch);
    if cfg!(target_os = "linux") {
        assert!(started(&answer), "{answer}");
        assert_eq!(report(&answer)["vars"][KEY], w.key_digest());
    } else {
        assert_eq!(error_of(&answer), "runner_unavailable", "{answer}");
        assert_eq!(w.released(), (0, 0));
    }
    assert!(
        !appears(&wrong, Duration::from_secs(1)),
        "the replacement ran"
    );
    // Another build of envcloak, and a new daemon, which takes it.
    let other = bins.join("envcloak.other");
    std::fs::copy(envcloak_e2e::bin_dir().join("envcloak"), &other).unwrap();
    if cfg!(target_os = "macos") {
        let signed = std::process::Command::new("/usr/bin/codesign")
            .args(["-f", "-s", "-", "-i", "ec.envcloak.other"])
            .arg(&other)
            .output()
            .unwrap();
        assert!(signed.status.success(), "{}", text(&signed));
    } else {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&other)
            .unwrap();
        f.write_all(b"another build").unwrap();
    }
    std::fs::rename(&other, bins.join("envcloak")).unwrap();
    let _ = w.h.stop_daemon();
    w.h.start_daemon(&[]);
    // The new daemon's vault is locked: the person unlocks it.
    let pass =
        w.h.secret_file(envcloak_testkit::labels::VAULT_PASSPHRASE, true);
    let home = w.h.home.home();
    let unlocked = w.h.human(
        &home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(unlocked.code, 0, "{}", unlocked.all());
    if cfg!(target_os = "linux") {
        // The new daemon took the new file: its anchor's digest.
        let digest = sha256_hex(&std::fs::read(bins.join("envcloak")).unwrap());
        w.h.expect_log(&format!("anchor sha256 {digest}"), Duration::from_secs(10));
    }
    let again = w.request(&launch);
    let id = pending_id(&again);
    w.approve(&id);
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    assert_eq!(report(&answer)["vars"][KEY], w.key_digest());
    w.h.assert_swept("after the anchor's replacement");
}

/// D-36's consequence: a command the managed server starts runs outside
/// the agent's and the person's process trees, a descendant of the daemon
/// with no terminal: it is classed `unknown`. Its proof is refused
/// (`envcloak approve` from it is `proof_refused`), and no terminal grant
/// covers its request, which is pending as an unknown subject's.
#[test]
fn a_command_the_server_starts_is_unknown() {
    if managed_common::release_run("a_command_the_server_starts_is_unknown") {
        return;
    }
    let mut w = World::new(&[]);
    // Another, unmanaged project binding the same key.
    let other = w.h.home.root().join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(
        other.join("envcloak.toml"),
        format!("[project]\nname = \"other\"\n\n[env]\n{KEY} = \"stripe/fixture\"\n"),
    )
    .unwrap();
    // The server's environment is the launch's: the runtime directory, so
    // its commands find the daemon's socket, is declared.
    let runtime = w.h.home.root().join("run");
    let argv = w.fixture_argv();
    let reg = w.register(json!({
        "argv": argv,
        "env": [["XDG_RUNTIME_DIR", runtime.to_str().unwrap()]],
    }));
    let launch = reg["launch"].as_str().unwrap().to_owned();
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let cli = w.h.cli();
    let cli = cli.to_str().unwrap();
    let manifest = other.join("envcloak.toml");
    let approve = json!([cli, "approve", "AAAAAAAA"]).to_string();
    let run = json!([
        cli,
        "run",
        "--manifest",
        manifest.to_str().unwrap(),
        "--",
        "true"
    ])
    .to_string();
    let answer = w.agent(
        "request",
        &json!({
            "launch": launch,
            "send": ["report", format!("spawn {approve}"), format!("spawn {run}")],
        }),
    );
    assert!(started(&answer), "{answer}");
    let approved = report_at(&answer, 1);
    assert!(
        approved["stderr"]
            .as_str()
            .unwrap_or("")
            .starts_with("envcloak: proof_refused: "),
        "{answer}"
    );
    let ran = report_at(&answer, 2);
    assert_eq!(ran["code"], 125, "{answer}");
    assert!(
        ran["stderr"]
            .as_str()
            .unwrap_or("")
            .contains("approval_required"),
        "{answer}"
    );
    let home = w.h.home.home();
    let listed = w.h.human(&home, &["pending", "--json"], &[], &[]);
    assert_eq!(listed.code, 0, "{}", listed.all());
    let listed: Value = serde_json::from_str(&listed.out()).unwrap();
    let other_dir = std::fs::canonicalize(&other).unwrap();
    let request = listed["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["project"] == other_dir.to_str().unwrap())
        .unwrap_or_else(|| panic!("no pending request for the other project: {listed}"));
    assert_eq!(request["kind"], "unknown", "{listed}");
}
