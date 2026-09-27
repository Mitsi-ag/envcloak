//! Gate 19 (process hardening) for the `envcloak` binary, observed from
//! outside the process: core dumps are off and a forced abort leaves no core;
//! on Linux a same-uid ptrace attach and reads of `/proc/<pid>/mem` and
//! `environ` are denied; on macOS a copy signed with the hardened runtime
//! reports it. Each check that can only pass vacuously in a hostile test
//! environment runs a control process first.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};

use envcloak_testkit::{TestHome, by_label, canaries, fresh_seed, labels};

fn cli() -> &'static str {
    env!("CARGO_BIN_EXE_envcloak")
}

fn report_of(program: &Path, home: &TestHome) -> String {
    let out = home
        .apply(&mut Command::new(program))
        .args(["internal", "hardening"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// A process held alive for inspection. Killed on drop.
struct Held {
    child: Child,
    _stdin: ChildStdin,
    report: String,
}

impl Held {
    fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).unwrap()
    }

    fn signal(&self, sig: &str) {
        let pid = self.pid().to_string();
        let ok = Command::new("kill")
            .args([sig, &pid])
            .status()
            .unwrap()
            .success();
        assert!(ok, "kill {sig} failed");
    }

    fn wait(mut self) -> ExitStatus {
        self.child.wait().unwrap()
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts `script` under `sh` in `cwd` with core dumps raised as far as the
/// hard limit allows, and waits for the line `ready`. Earlier lines are kept
/// as the report.
fn hold(home: &TestHome, cwd: &Path, script: &str, arg0: &str, env: &[(&str, &str)]) -> Held {
    let full = format!(
        "ulimit -c unlimited 2>/dev/null || ulimit -c \"$(ulimit -H -c)\" 2>/dev/null; {script}"
    );
    let mut cmd = Command::new("sh");
    home.apply(&mut cmd)
        .args(["-c", &full, arg0])
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let stdin = child.stdin.take().unwrap();
    let mut report = String::new();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    loop {
        match lines.next() {
            Some(Ok(line)) if line == "ready" => break,
            Some(Ok(line)) => {
                report.push_str(&line);
                report.push('\n');
            }
            _ => panic!("process exited before it was ready; output so far:\n{report}"),
        }
    }
    Held {
        child,
        _stdin: stdin,
        report,
    }
}

fn hold_cli(home: &TestHome, cwd: &Path, env: &[(&str, &str)]) -> Held {
    hold(
        home,
        cwd,
        "exec \"$0\" internal hardening --hold",
        cli(),
        env,
    )
}

/// Core files a crash of `pid` could have left in `cwd` (or in `/cores` on
/// macOS).
fn core_files(cwd: &Path, pid: i32) -> Vec<String> {
    let mut found: Vec<String> = std::fs::read_dir(cwd)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n == "core" || n.starts_with("core."))
        .collect();
    let mac = format!("/cores/core.{pid}");
    if Path::new(&mac).exists() {
        found.push(mac);
    }
    found
}

#[test]
fn cli_reports_hardening_and_the_wiping_allocator() {
    let home = TestHome::new();
    let report = report_of(Path::new(cli()), &home);
    assert!(report.contains("core_dumps_off=true\n"), "{report}");
    assert!(report.contains("rlimit_core=0/0\n"), "{report}");
    assert!(report.contains("tracer_present=false\n"), "{report}");
    assert!(report.contains("wiping_allocator=true\n"), "{report}");
    if cfg!(target_os = "linux") {
        assert!(report.contains("non_dumpable=true\n"), "{report}");
        assert!(report.contains("hardened_runtime=n/a\n"), "{report}");
    }
    if cfg!(target_os = "macos") {
        // Cargo builds are not signed with the hardened runtime, and the
        // report says so instead of claiming protection.
        assert!(report.contains("hardened_runtime=false\n"), "{report}");
    }
}

#[test]
fn unknown_arguments_are_never_echoed() {
    let cs = canaries(fresh_seed());
    let secret = by_label(&cs, labels::OPENAI_API_KEY).as_str();
    let home = TestHome::new();
    let out = home
        .apply(&mut Command::new(cli()))
        .args(["add", secret])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    envcloak_testkit::assert_no_canary(&out.stdout, &cs);
    envcloak_testkit::assert_no_canary(&out.stderr, &cs);
}

#[test]
fn forced_abort_leaves_no_core_file() {
    let home = TestHome::new();

    // Control: an unhardened process under the same limits. Whether it
    // dumps depends on the machine (core_pattern, /cores permissions); the
    // assertion below only means something where it does, so say which.
    let control_dir = home.root().join("tmp");
    let control = hold(&home, &control_dir, "echo ready; exec sleep 60", "sh", &[]);
    let control_pid = control.pid();
    control.signal("-ABRT");
    let control_status = control.wait();
    let control_dumped =
        control_status.core_dumped_flag() || !core_files(&control_dir, control_pid).is_empty();
    eprintln!("control process dumped core: {control_dumped}");

    let cwd = home.home();
    let held = hold_cli(&home, &cwd, &[]);
    assert!(held.report.contains("rlimit_core=0/0\n"), "{}", held.report);
    let pid = held.pid();
    held.signal("-ABRT");
    let status = held.wait();
    assert_eq!(status.signal_number(), Some(6), "{status:?}");
    assert!(
        !status.core_dumped_flag(),
        "the kernel reported a core dump"
    );
    assert!(
        core_files(&cwd, pid).is_empty(),
        "{:?}",
        core_files(&cwd, pid)
    );
}

trait StatusExt {
    fn signal_number(&self) -> Option<i32>;
    fn core_dumped_flag(&self) -> bool;
}

impl StatusExt for ExitStatus {
    fn signal_number(&self) -> Option<i32> {
        std::os::unix::process::ExitStatusExt::signal(self)
    }

    fn core_dumped_flag(&self) -> bool {
        std::os::unix::process::ExitStatusExt::core_dumped(self)
    }
}

#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    let out = Command::new("id").arg("-u").output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim() == "0"
}

#[cfg(target_os = "linux")]
#[test]
fn linux_same_uid_ptrace_and_proc_reads_are_denied() {
    use envcloak_sys::testing::try_attach;

    if running_as_root() {
        eprintln!("skipped: root bypasses the dumpable check");
        return;
    }
    let cs = canaries(fresh_seed());
    let secret = by_label(&cs, labels::GITHUB_TOKEN).as_str();
    let env = [("ENVCLOAK_TEST_CANARY", secret)];
    let home = TestHome::new();

    // Control: an ordinary child of this process can be attached to and
    // read, and its environment holds the canary. Without this, a denial
    // below could come from the environment (Yama scope 2 or 3, a
    // container) rather than from the CLI's hardening.
    let control = hold(&home, &home.home(), "echo ready; exec cat", "sh", &env);
    let cpid = control.pid();
    try_attach(cpid).expect("control: ptrace attach to an ordinary child must work here");
    std::fs::File::open(format!("/proc/{cpid}/mem")).expect("control: /proc/<pid>/mem");
    let environ = std::fs::read(format!("/proc/{cpid}/environ")).expect("control: environ");
    assert!(
        !envcloak_testkit::find(&environ, &cs).is_empty(),
        "control: the canary must be visible in an ordinary environ"
    );
    drop(control);

    let held = hold_cli(&home, &home.home(), &env);
    assert!(
        held.report.contains("non_dumpable=true\n"),
        "{}",
        held.report
    );
    let pid = held.pid();

    let err = try_attach(pid).expect_err("ptrace attach to the CLI must be denied");
    assert_eq!(err.raw_os_error(), Some(libc_eperm()), "{err}");
    let err = std::fs::File::open(format!("/proc/{pid}/mem")).expect_err("mem must be denied");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    let err = std::fs::read(format!("/proc/{pid}/environ")).expect_err("environ must be denied");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
}

#[cfg(target_os = "linux")]
fn libc_eperm() -> i32 {
    1
}

#[cfg(target_os = "macos")]
#[test]
fn macos_signed_copy_reports_the_hardened_runtime_without_get_task_allow() {
    let home = TestHome::new();
    let copy = home.root().join("tmp").join("envcloak");
    std::fs::copy(cli(), &copy).unwrap();
    let signed = Command::new("codesign")
        .args(["--force", "--sign", "-", "--options", "runtime"])
        .arg(&copy)
        .status()
        .unwrap();
    assert!(signed.success(), "codesign failed");
    let report = report_of(&copy, &home);
    assert!(report.contains("hardened_runtime=true\n"), "{report}");
    let ents = Command::new("codesign")
        .args(["-d", "--entitlements", "-"])
        .arg(&copy)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&ents.stdout),
        String::from_utf8_lossy(&ents.stderr)
    );
    assert!(!text.contains("get-task-allow"), "{text}");
}
