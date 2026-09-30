//! The release-profile artifacts (SPEC §5 "Process hardening", §15.2 gates
//! 12 and 19; M1 acceptance): `envcloak` and `envcloakd` as
//! `cargo build --release` makes them, in `ENVCLOAK_TEST_RELEASE_DIR`
//! (CI's release job builds them and sets it; elsewhere these tests say
//! they were skipped).
//!
//! - `panic = "abort"`: a panic ends the process with SIGABRT, where the
//!   test build (the control) unwinds and exits 101; the panic handler
//!   prints its place and never its message, which holds a fixture here.
//! - The core-dump test: started with the core limit raised as far as the
//!   hard limit allows, and on macOS signed with `get-task-allow` (without
//!   which the kernel never writes a core), a release binary that aborts
//!   leaves no core file. The positive control, an ordinary process started
//!   the same way, does dump core where `ENVCLOAK_TEST_CORE_DIR` names the
//!   kernel's core directory (CI sets it on both systems).
//! - No test hook is shipped: the names of the test-only variables are in
//!   the test build (the control) and nowhere in the release artifacts.
//! - `envcloak status` and `internal hardening` say truthfully what the
//!   build has: "daemon identity unverified" (no M1 build pins a code
//!   signature), and "unhardened" where the independent view (`codesign`
//!   on macOS, `/proc` on Linux) says so.
#![allow(clippy::unwrap_used)]

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use envcloak_e2e::{Harness, finish_within, target_dir, text};
#[cfg(target_os = "macos")]
use envcloak_testkit::crash::signed_copy;
use envcloak_testkit::crash::{CoreFiles, RAISE_CORE_LIMIT, StatusExt, core_dump_dir};
use envcloak_testkit::{TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels};

/// The release build's directory, or `None` (and a note) when it is not
/// given. In CI's release job it must be.
fn release_dir(test: &str) -> Option<PathBuf> {
    let Some(dir) = std::env::var_os("ENVCLOAK_TEST_RELEASE_DIR").map(PathBuf::from) else {
        assert!(
            std::env::var_os("ENVCLOAK_TEST_REQUIRE_RELEASE").is_none(),
            "ENVCLOAK_TEST_REQUIRE_RELEASE is set but ENVCLOAK_TEST_RELEASE_DIR is not"
        );
        eprintln!("{test}: skipped; set ENVCLOAK_TEST_RELEASE_DIR to the release build");
        return None;
    };
    for name in ["envcloak", "envcloakd"] {
        assert!(
            dir.join(name).is_file(),
            "no {name} in the release directory"
        );
    }
    Some(dir)
}

/// The test build of `name`, the control: the binary `cargo test` built
/// with the test-only features, no older than its sources (review G3-V2).
fn test_build(name: &str) -> PathBuf {
    let p = target_dir().join(name);
    assert!(
        p.is_file(),
        "{} is missing: build the test binaries first (cargo build -p envcloak -p envcloakd \
         -p envcloak-testkit --bins)",
        p.display()
    );
    envcloak_testkit::assert_fresh(&p, name);
    p
}

const CONTROL_ENV: &str = "ENVCLOAK_TEST_ABORT_CONTROL";

/// Runs only as the positive core-dump control: aborts at once.
#[test]
fn abort_control_child() {
    if std::env::var_os(CONTROL_ENV).is_some() {
        std::process::abort();
    }
}

/// `program internal panic` under `sh` with the core limit raised, in
/// `home`'s cleared environment, `cwd` its directory, standard input from
/// `payload`. Returns the status, the pid and standard error.
fn panic_under_raised_limit(
    home: &TestHome,
    cwd: &Path,
    program: &Path,
    payload: &Path,
) -> (std::process::ExitStatus, i32, Vec<u8>) {
    let mut cmd = Command::new("sh");
    home.apply(&mut cmd)
        .args([
            "-c",
            &format!("{RAISE_CORE_LIMIT}exec \"$0\" internal panic"),
            program.to_str().unwrap(),
        ])
        .current_dir(cwd)
        .stdin(Stdio::from(std::fs::File::open(payload).unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.stdout.is_empty());
    (out.status, pid, out.stderr)
}

#[test]
fn release_artifacts_abort_on_a_panic_and_leave_no_core() {
    let Some(release) = release_dir("release_artifacts_abort_on_a_panic_and_leave_no_core") else {
        return;
    };
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let files = tempfile::Builder::new()
        .prefix("ecf")
        .tempdir_in("/tmp")
        .unwrap();
    let payload = files.path().join("payload");
    std::fs::write(&payload, by_label(&cs, labels::OPENAI_API_KEY).value()).unwrap();
    let tmp = home.root().join("tmp");
    let dumps = core_dump_dir();
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        assert!(
            dumps.is_some(),
            "CI must run the positive core-dump control"
        );
    }

    // Positive control: an ordinary process, started and signed the same
    // way, dumps core, so "no core file" below means something.
    if let Some(dir) = &dumps {
        let this = std::env::current_exe().unwrap();
        #[cfg(target_os = "macos")]
        let this = signed_copy(&this, &tmp, "control", false, true);
        let mut cmd = Command::new("sh");
        home.apply(&mut cmd)
            .args([
                "-c",
                &format!("{RAISE_CORE_LIMIT}exec \"$0\" --exact abort_control_child --nocapture"),
                this.to_str().unwrap(),
            ])
            .env(CONTROL_ENV, "1")
            .current_dir(&tmp)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let cores = CoreFiles::before(&tmp, Some(dir));
        let child = cmd.spawn().unwrap();
        let pid = child.id();
        let status = child.wait_with_output().unwrap().status;
        let left = cores.left(i32::try_from(pid).unwrap());
        for p in &left {
            let _ = std::fs::remove_file(p);
        }
        let written = left.contains(&dir.join(format!("core.{pid}")));
        assert!(
            status.core_dumped_flag() && written,
            "control: an ordinary process must dump core into {} ({status:?}, written: {written})",
            dir.display()
        );
    } else {
        eprintln!("the positive core-dump control is unverified; set ENVCLOAK_TEST_CORE_DIR");
    }

    for (name, prefix) in [("envcloak", "envcloak:"), ("envcloakd", "envcloakd:")] {
        // The test build unwinds and exits 101: the control for abort.
        let (status, _, err) = panic_under_raised_limit(&home, &tmp, &test_build(name), &payload);
        assert_no_canary(&err, &cs);
        assert_eq!(status.code(), Some(101), "{name} (test build): {status:?}");

        let program = release.join(name);
        #[cfg(target_os = "macos")]
        let program = signed_copy(&program, &tmp, name, false, true);
        let cores = CoreFiles::before(&tmp, dumps.as_deref());
        let (status, pid, err) = panic_under_raised_limit(&home, &tmp, &program, &payload);
        assert_no_canary(&err, &cs);
        assert_eq!(
            status.signal(),
            Some(libc::SIGABRT),
            "{name}: a release build must abort on a panic: {status:?}"
        );
        let err = String::from_utf8_lossy(&err).into_owned();
        assert!(
            err.starts_with(&format!("{prefix} internal error: a panic at "))
                && err
                    .trim_end()
                    .ends_with("its message is not shown, since it could hold a secret")
                && err.lines().count() == 1,
            "{name}: {err}"
        );
        let left = cores.left(pid);
        for p in &left {
            let _ = std::fs::remove_file(p);
        }
        assert!(
            !status.core_dumped_flag(),
            "{name}: the kernel reported a core dump"
        );
        assert!(left.is_empty(), "{name}: core files {left:?}");
    }
    home.assert_clean(&cs);
}

/// Whether `bytes` holds `needle`.
fn holds(bytes: &[u8], needle: &str) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn release_artifacts_carry_no_test_hook() {
    let Some(release) = release_dir("release_artifacts_carry_no_test_hook") else {
        return;
    };
    // The variables of the test-only hooks, as the source names them: the
    // injected panics (envcloak-sys, in both binaries) and gate 16's pause
    // points (envcloak-scan, in the CLI). The test build of both binaries
    // has the first, which shows the search finds such a name.
    for name in ["envcloak", "envcloakd"] {
        let test = std::fs::read(test_build(name)).unwrap();
        assert!(
            holds(&test, "ENVCLOAK_TEST_PANIC"),
            "control: the test build of {name} has the panic hook"
        );
        let shipped = std::fs::read(release.join(name)).unwrap();
        for hook in ["ENVCLOAK_TEST_PANIC", "ENVCLOAK_TEST_PAUSE_DIR"] {
            assert!(!holds(&shipped, hook), "the release {name} holds {hook}");
        }
    }
}

/// What `internal hardening` of `program` reports.
fn report(home: &TestHome, program: &Path) -> String {
    let mut cmd = Command::new(program);
    home.apply(&mut cmd)
        .args(["internal", "hardening"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = finish_within(cmd, Duration::from_secs(60));
    assert!(out.status.success(), "{}", text(&out));
    String::from_utf8(out.stdout).unwrap()
}

/// Whether `exe` is signed with the hardened runtime (`codesign`).
fn hardened_runtime(exe: &Path) -> bool {
    let out = Command::new("codesign")
        .args(["--display", "--verbose=2"])
        .arg(exe)
        .output()
        .unwrap();
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    shown
        .lines()
        .filter(|l| l.starts_with("CodeDirectory "))
        .any(|l| l.contains("runtime"))
}

#[test]
fn release_status_says_what_the_build_cannot_guarantee() {
    let Some(release) = release_dir("release_status_says_what_the_build_cannot_guarantee") else {
        return;
    };
    let home = TestHome::new();
    for name in ["envcloak", "envcloakd"] {
        let r = report(&home, &release.join(name));
        assert!(r.contains("core_dumps_off=true\n"), "{name}: {r}");
        assert!(r.contains("rlimit_core=0/0\n"), "{name}: {r}");
        assert!(r.contains("wiping_allocator=true\n"), "{name}: {r}");
        assert!(r.contains("tracer_present=false\n"), "{name}: {r}");
        if cfg!(target_os = "linux") {
            assert!(r.contains("non_dumpable=true\n"), "{name}: {r}");
        }
        if cfg!(target_os = "macos") {
            let signed = hardened_runtime(&release.join(name));
            assert!(
                r.contains(&format!("hardened_runtime={signed}\n")),
                "{name}: {r}"
            );
        }
    }

    // The daemon and the CLI of the release build, as a user runs them.
    let mut h = Harness::start();
    assert_eq!(
        h.cli(),
        release.join("envcloak"),
        "set ENVCLOAK_E2E_BIN_DIR too"
    );
    let dir = h.home.home();
    let o = h.agent(&dir, &["status"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let st = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        st.contains("daemon identity: unverified (this build pins no code signature"),
        "{st}"
    );
    let daemon = st
        .lines()
        .find_map(|l| l.strip_prefix("daemon hardening: "))
        .unwrap_or("")
        .to_owned();
    let cli = st
        .lines()
        .find_map(|l| l.strip_prefix("cli hardening: "))
        .unwrap_or("")
        .to_owned();
    if cfg!(target_os = "macos") {
        for (line, exe) in [(&daemon, h.daemon_exe()), (&cli, h.cli())] {
            let want = if hardened_runtime(&exe) {
                "hardened"
            } else {
                "unhardened (not signed with the hardened runtime)"
            };
            assert!(line.starts_with(want), "{line}");
        }
    } else {
        // Non-dumpable: the daemon's /proc entries belong to root; its
        // core limit is 0.
        let pid = h.daemon.pid();
        let owner = std::os::unix::fs::MetadataExt::uid(
            &std::fs::metadata(format!("/proc/{pid}/status")).unwrap(),
        );
        let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
        let core_off = limits
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .is_some_and(|l| l.split_whitespace().nth(4) == Some("0"));
        let want = if owner == 0 && core_off {
            "hardened"
        } else {
            "unhardened"
        };
        assert!(daemon.starts_with(want), "{daemon}");
        assert_eq!(cli, "hardened", "{st}");
    }
    h.assert_swept("release status");
}
