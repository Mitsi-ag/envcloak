//! Gate 19 (process hardening) for `envcloakd`, observed from outside the
//! serving daemon: it installs the wiping allocator and turns core dumps
//! off; a forced abort leaves no core file; on Linux a same-uid ptrace
//! attach and reads of `/proc/<pid>/mem` and `environ` are denied, and a
//! daemon started under a tracer refuses to start; on macOS a copy signed
//! with the hardened runtime reports it. Each check that could pass
//! vacuously runs a control first; see `envcloak_testkit::crash` for the
//! core-dump control.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{client, exe};
use envcloak_testkit::crash::{CoreFiles, RAISE_CORE_LIMIT, StatusExt, core_dump_dir};
use envcloak_testkit::{Daemon, TestHome};

fn report_of(program: &Path, home: &TestHome) -> String {
    let out = home
        .apply(&mut Command::new(program))
        .args(["internal", "hardening"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn daemon_reports_hardening_and_the_wiping_allocator() {
    let home = TestHome::new();
    let report = report_of(Path::new(env!("CARGO_BIN_EXE_envcloakd")), &home);
    assert!(report.contains("wiping_allocator=true\n"), "{report}");
    assert!(report.contains("core_dumps_off=true\n"), "{report}");
    assert!(report.contains("rlimit_core=0/0\n"), "{report}");
    assert!(report.contains("tracer_present=false\n"), "{report}");
    if cfg!(target_os = "linux") {
        assert!(report.contains("non_dumpable=true\n"), "{report}");
    }
    if cfg!(target_os = "macos") {
        // Cargo builds are not signed with the hardened runtime, and the
        // daemon says so rather than claiming protection.
        assert!(report.contains("hardened_runtime=false\n"), "{report}");
    }

    // The serving daemon reports the same over its socket.
    let _d = Daemon::start(&home, exe(), &[]);
    let h = client(&home).status().unwrap().daemon.hardening;
    assert!(h.core_dumps_off);
    if cfg!(target_os = "linux") {
        assert!(h.non_dumpable);
        assert!(h.hardened());
    }
    if cfg!(target_os = "macos") {
        assert_eq!(h.hardened_runtime, Some(false));
        assert!(!h.hardened());
    }
}

/// Set in the environment of the positive core-dump control.
const CONTROL_ENV: &str = "ENVCLOAK_TEST_ABORT_CONTROL";

/// Runs only as the positive core-dump control: says it is ready, then
/// waits for the signal (or for stdin to close).
#[test]
fn abort_control_child() {
    if std::env::var_os(CONTROL_ENV).is_none() {
        return;
    }
    println!("\nready");
    let mut rest = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut rest);
}

/// The control program (this test binary) and the daemon to crash. On
/// macOS both are copies signed with `get-task-allow`, without which the
/// kernel never writes a core.
fn crash_subjects(dir: &Path) -> (PathBuf, PathBuf) {
    let this = std::env::current_exe().unwrap();
    #[cfg(target_os = "macos")]
    {
        use envcloak_testkit::crash::signed_copy;
        let control = signed_copy(&this, dir, "control", false, true);
        let program = signed_copy(exe(), dir, "envcloakd", false, true);
        (control, program)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = dir;
        (this, exe().to_path_buf())
    }
}

/// A shell in `home`'s environment that raises the core limit and runs
/// `program` with the shell's own arguments.
fn with_raised_limit(home: &TestHome, cwd: &Path, program: &Path) -> Command {
    let mut cmd = Command::new("sh");
    home.apply(&mut cmd)
        .args(["-c", &format!("{RAISE_CORE_LIMIT}exec \"$0\" \"$@\"")])
        .arg(program)
        .current_dir(cwd);
    cmd
}

#[test]
fn a_forced_abort_of_the_serving_daemon_leaves_no_core_file() {
    let home = TestHome::new();
    let dumps = core_dump_dir();
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        assert!(
            dumps.is_some(),
            "CI must run the positive core-dump control"
        );
    }
    let tmp = home.root().join("tmp");
    let (control_program, program) = crash_subjects(&tmp);

    match &dumps {
        // Positive control: an ordinary process, signed like the daemon and
        // started the same way, dumps core into the known directory.
        Some(dir) => {
            let mut cmd = with_raised_limit(&home, &tmp, &control_program);
            cmd.args([
                "--exact",
                "abort_control_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CONTROL_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
            let cores = CoreFiles::before(&tmp, Some(dir));
            let mut control = cmd.spawn().unwrap();
            let mut lines = BufReader::new(control.stdout.take().unwrap()).lines();
            assert!(lines.any(|l| l.is_ok_and(|l| l == "ready")));
            let pid = control.id();
            assert!(
                Command::new("kill")
                    .args(["-ABRT", &pid.to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            let status = control.wait().unwrap();
            let left = cores.left(i32::try_from(pid).unwrap());
            for path in &left {
                let _ = std::fs::remove_file(path);
            }
            let written = left.contains(&dir.join(format!("core.{pid}")));
            assert!(
                status.core_dumped_flag() && written,
                "control: an ordinary process must dump core into {} ({status:?}, file written: {written})",
                dir.display()
            );
        }
        None => eprintln!(
            "a_forced_abort_of_the_serving_daemon_leaves_no_core_file: positive control \
             unverified; set ENVCLOAK_TEST_CORE_DIR to run it"
        ),
    }

    // The daemon lowers the limit its parent shell raised, serves, and does
    // not dump when it aborts.
    let cwd = home.home();
    let cores = CoreFiles::before(&cwd, dumps.as_deref());
    let mut d = Daemon::start_command(with_raised_limit(&home, &cwd, &program), &[]);
    assert!(
        client(&home)
            .status()
            .unwrap()
            .daemon
            .hardening
            .core_dumps_off
    );
    let pid = d.pid();
    d.signal("-ABRT");
    let status = d.wait_exit(Duration::from_secs(20)).unwrap();
    assert_eq!(status.signal_number(), Some(6), "{status:?}");
    let left = cores.left(pid);
    for path in &left {
        let _ = std::fs::remove_file(path);
    }
    assert!(
        !status.core_dumped_flag(),
        "the kernel reported a core dump"
    );
    assert!(left.is_empty(), "{left:?}");
}

/// Waits up to `limit` for `child` to exit and returns its exit status and
/// standard error.
#[cfg(target_os = "linux")]
fn finish_within(
    mut child: std::process::Child,
    limit: Duration,
) -> (std::process::ExitStatus, String) {
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the process did not exit within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    if let Some(mut e) = child.stderr.take() {
        e.read_to_string(&mut stderr).unwrap();
    }
    (status, stderr)
}

#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    let out = Command::new("id").arg("-u").output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim() == "0"
}

#[cfg(target_os = "linux")]
#[test]
fn linux_same_uid_ptrace_and_proc_reads_of_the_daemon_are_denied() {
    use envcloak_sys::testing::try_attach;
    use envcloak_testkit::{by_label, canaries, fresh_seed, labels};

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
    let home = TestHome::new();

    // Control: an ordinary child of this process can be attached to and
    // read, and its environment holds the canary.
    let mut control = home
        .apply(&mut Command::new("sh"))
        .args(["-c", "echo ready; exec cat"])
        .env("ENVCLOAK_TEST_CANARY", secret)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(control.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let cpid = i32::try_from(control.id()).unwrap();
    try_attach(cpid).expect("control: ptrace attach to an ordinary child must work here");
    std::fs::File::open(format!("/proc/{cpid}/mem")).expect("control: /proc/<pid>/mem");
    let environ = std::fs::read(format!("/proc/{cpid}/environ")).expect("control: environ");
    assert!(!envcloak_testkit::find(&environ, &cs).is_empty());
    let _ = control.kill();
    let _ = control.wait();

    let mut cmd = Command::new(exe());
    home.apply(&mut cmd).env("ENVCLOAK_TEST_CANARY", secret);
    let d = Daemon::start_command(cmd, &[]);
    let pid = d.pid();
    let err = try_attach(pid).expect_err("ptrace attach to the daemon must be denied");
    assert_eq!(err.raw_os_error(), Some(1), "{err}");
    let err = std::fs::File::open(format!("/proc/{pid}/mem")).expect_err("mem must be denied");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    let err = std::fs::read(format!("/proc/{pid}/environ")).expect_err("environ must be denied");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
}

/// A daemon started under a tracer (as under `strace` or `gdb`, which
/// non-dumpable cannot keep out) refuses to start, before it creates its
/// socket. The untraced control is every other test here.
#[cfg(target_os = "linux")]
#[test]
fn linux_a_traced_daemon_refuses_to_start() {
    use envcloak_sys::testing::spawn_traced;

    let home = TestHome::new();
    let mut cmd = Command::new(exe());
    home.apply(&mut cmd)
        .arg("--foreground")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let (status, stderr) = finish_within(spawn_traced(&mut cmd).unwrap(), Duration::from_secs(30));
    assert_eq!(status.code(), Some(1), "{status:?}: {stderr}");
    assert!(stderr.starts_with("envcloakd: traced:"), "{stderr}");
    assert!(!envcloak_testkit::daemon_socket(&home).exists());
}

#[cfg(target_os = "macos")]
#[test]
fn macos_signed_daemon_copy_reports_the_hardened_runtime() {
    use envcloak_testkit::crash::signed_copy;

    let home = TestHome::new();
    let tmp = home.root().join("tmp");
    let copy = signed_copy(exe(), &tmp, "envcloakd", true, false);
    let report = report_of(&copy, &home);
    assert!(report.contains("hardened_runtime=true\n"), "{report}");

    // Negative control: the runtime with get-task-allow is not protected.
    let copy = signed_copy(exe(), &tmp, "envcloakd-debuggable", true, true);
    let report = report_of(&copy, &home);
    assert!(report.contains("hardened_runtime=false\n"), "{report}");

    // The signed daemon, serving, reports it over the socket too.
    let copy = signed_copy(exe(), &tmp, "envcloakd-signed", true, false);
    let _d = Daemon::start(&home, &copy, &[]);
    let h = client(&home).status().unwrap().daemon.hardening;
    assert_eq!(h.hardened_runtime, Some(true));
    assert!(h.hardened());
}
