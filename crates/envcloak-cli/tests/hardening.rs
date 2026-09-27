//! Gate 19 (process hardening) for the `envcloak` binary, observed from
//! outside the process: core dumps are off and a forced abort leaves no core;
//! on Linux a same-uid ptrace attach and reads of `/proc/<pid>/mem` and
//! `environ` are denied; on macOS a copy signed with the hardened runtime
//! reports it. Each check that can only pass vacuously in a hostile test
//! environment runs a control process first.
//!
//! Every process these tests start runs in [`TestHome::apply`]'s cleared
//! environment, so no core file can hold anything from the developer's
//! shell. The positive core-dump control deliberately crashes a process, so
//! it runs only where core files go to a known directory: set
//! `ENVCLOAK_TEST_CORE_DIR` to a directory the kernel's core pattern writes
//! `core.<pid>` files into (CI does this on Linux). Elsewhere the test says
//! the control is unverified.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
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

/// A process held alive for inspection until its stdin closes. Killed on
/// drop.
struct Held {
    child: Child,
    stdin: Option<ChildStdin>,
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

    /// Closes stdin, which lets the process exit, and waits for it.
    fn release(mut self) -> ExitStatus {
        drop(self.stdin.take());
        self.child.wait().unwrap()
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Shell prefix that raises the core limit as far as the hard limit allows.
/// Only ever used in [`TestHome::apply`]'s cleared environment.
const RAISE_CORE_LIMIT: &str =
    "ulimit -c unlimited 2>/dev/null || ulimit -c \"$(ulimit -H -c)\" 2>/dev/null; ";

/// Starts `script` under `sh` in `cwd`, in `home`'s cleared environment plus
/// `env`, and waits for the line `ready`. Earlier lines are kept as the
/// report.
fn hold(home: &TestHome, cwd: &Path, script: &str, arg0: &str, env: &[(&str, &str)]) -> Held {
    let mut cmd = Command::new("sh");
    home.apply(&mut cmd)
        .args(["-c", script, arg0])
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    held(cmd.spawn().unwrap())
}

/// Waits for `child` to print the line `ready`. Earlier lines are kept as
/// the report.
fn held(mut child: Child) -> Held {
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
        stdin: Some(stdin),
        report,
    }
}

/// Holds the CLI, started by a shell that ran `prelude` first.
fn hold_cli(home: &TestHome, cwd: &Path, prelude: &str, env: &[(&str, &str)]) -> Held {
    let script = format!("{prelude}exec \"$0\" internal hardening --hold");
    hold(home, cwd, &script, cli(), env)
}

/// The directory the kernel writes `core.<pid>` files into, when the
/// environment names one (see the module documentation).
fn core_dump_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("ENVCLOAK_TEST_CORE_DIR")?);
    assert!(dir.is_dir(), "ENVCLOAK_TEST_CORE_DIR is not a directory");
    #[cfg(target_os = "linux")]
    {
        let pattern = std::fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap();
        assert!(
            Path::new(pattern.trim()).starts_with(&dir),
            "ENVCLOAK_TEST_CORE_DIR is set, but kernel.core_pattern is {pattern:?}"
        );
    }
    Some(dir)
}

/// Core files a crash of `pid` could have left: `core` or `core.*` in
/// `cwd`, `/cores/core.<pid>` (macOS), and `core.<pid>` in `dumps`.
fn core_files(cwd: &Path, dumps: Option<&Path>, pid: i32) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(cwd)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name == "core" || name.starts_with("core.")
        })
        .map(|e| e.path())
        .collect();
    let mut elsewhere = vec![PathBuf::from(format!("/cores/core.{pid}"))];
    elsewhere.extend(dumps.map(|d| d.join(format!("core.{pid}"))));
    found.extend(elsewhere.into_iter().filter(|p| p.exists()));
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

    // The held form reports the same, and exits once stdin closes.
    let held = hold_cli(&home, &home.home(), "", &[]);
    assert_eq!(held.report, report);
    let status = held.release();
    assert!(status.success(), "{status:?}");
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
    let dumps = core_dump_dir();
    if cfg!(target_os = "linux") && std::env::var_os("GITHUB_ACTIONS").is_some() {
        assert!(
            dumps.is_some(),
            "CI must run the positive core-dump control"
        );
    }

    match &dumps {
        // Positive control: an ordinary process with the same raised limit
        // and the same cleared environment dumps core into the known
        // directory. Without it, "no core file" could mean only that this
        // machine never writes any.
        Some(dir) => {
            let script = format!("{RAISE_CORE_LIMIT}echo ready; exec sleep 60");
            let control = hold(&home, &home.root().join("tmp"), &script, "sh", &[]);
            let pid = control.pid();
            control.signal("-ABRT");
            let status = control.wait();
            let core = dir.join(format!("core.{pid}"));
            let written = core.exists();
            let _ = std::fs::remove_file(&core);
            assert!(
                status.core_dumped_flag() && written,
                "control: an ordinary process must dump core into {} ({status:?}, file written: {written})",
                dir.display()
            );
        }
        None => eprintln!(
            "forced_abort_leaves_no_core_file: positive control unverified; \
             set ENVCLOAK_TEST_CORE_DIR to run it"
        ),
    }

    // The CLI lowers the limit its parent shell raised, and does not dump.
    let cwd = home.home();
    let held = hold_cli(&home, &cwd, RAISE_CORE_LIMIT, &[]);
    assert!(held.report.contains("rlimit_core=0/0\n"), "{}", held.report);
    let pid = held.pid();
    held.signal("-ABRT");
    let status = held.wait();
    assert_eq!(status.signal_number(), Some(6), "{status:?}");
    let left = core_files(&cwd, dumps.as_deref(), pid);
    for path in &left {
        let _ = std::fs::remove_file(path);
    }
    assert!(
        !status.core_dumped_flag(),
        "the kernel reported a core dump"
    );
    assert!(left.is_empty(), "{left:?}");
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
        assert!(
            std::env::var_os("GITHUB_ACTIONS").is_none(),
            "CI must run this check as an ordinary user"
        );
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

    let held = hold_cli(&home, &home.home(), "", &env);
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

/// Gate 19 also asks that a traced CLI refuse to request values. There is
/// no value path before T12, which owns that refusal test. This checks what
/// the refusal rests on: a CLI that starts under a tracer (as under `strace`
/// or `gdb`, which non-dumpable cannot keep out) reports it, while
/// `cli_reports_hardening_and_the_wiping_allocator` sees
/// `tracer_present=false` without one.
#[cfg(target_os = "linux")]
#[test]
fn linux_a_cli_started_under_a_tracer_reports_it() {
    use envcloak_sys::testing::spawn_traced;

    let home = TestHome::new();
    let mut cmd = Command::new(cli());
    home.apply(&mut cmd)
        .args(["internal", "hardening", "--hold"])
        .current_dir(home.home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let held = held(spawn_traced(&mut cmd).unwrap());
    assert!(
        held.report.contains("tracer_present=true\n"),
        "{}",
        held.report
    );
    assert!(
        held.report.contains("non_dumpable=true\n"),
        "{}",
        held.report
    );
    let status = held.release();
    assert!(status.success(), "{status:?}");
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
