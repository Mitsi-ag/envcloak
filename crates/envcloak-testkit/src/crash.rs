//! Helpers for gate 19's crash and code-signing checks (SPEC §5 "Process
//! hardening"), shared by the tests of both binaries.
//!
//! The positive core-dump control deliberately crashes a process, so it
//! runs only where core files go to a known directory: set
//! `ENVCLOAK_TEST_CORE_DIR` to a directory the kernel writes `core.<pid>`
//! files into (Linux `kernel.core_pattern`, macOS `kern.corefile`; CI does
//! this on both). macOS writes a core only for a process signed with
//! `get-task-allow`, so there the control and the program under test are
//! copies signed with it ([`signed_copy`]).

use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
use std::process::ExitStatus;

/// Shell prefix that raises the core limit as far as the hard limit
/// allows. Use it only in [`crate::TestHome::apply`]'s cleared environment.
pub const RAISE_CORE_LIMIT: &str =
    "ulimit -c unlimited 2>/dev/null || ulimit -c \"$(ulimit -H -c)\" 2>/dev/null; ";

/// The directory the kernel writes `core.<pid>` files into, when the
/// environment names one (see the module documentation).
///
/// # Panics
/// When `ENVCLOAK_TEST_CORE_DIR` is set but the kernel is not configured
/// to write there.
pub fn core_dump_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("ENVCLOAK_TEST_CORE_DIR")?);
    assert!(dir.is_dir(), "ENVCLOAK_TEST_CORE_DIR is not a directory");
    #[cfg(target_os = "linux")]
    {
        let pattern = std::fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap_or_default();
        assert!(
            Path::new(pattern.trim()).starts_with(&dir),
            "ENVCLOAK_TEST_CORE_DIR is set, but kernel.core_pattern is {pattern:?}"
        );
    }
    #[cfg(target_os = "macos")]
    {
        let sysctl = |name: &str| {
            let out = Command::new("/usr/sbin/sysctl")
                .args(["-n", name])
                .output()
                .unwrap_or_else(|e| panic!("sysctl {name}: {e}"));
            assert!(out.status.success(), "sysctl {name}: {out:?}");
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        assert_eq!(
            sysctl("kern.coredump"),
            "1",
            "ENVCLOAK_TEST_CORE_DIR is set, but kern.coredump is off"
        );
        let pattern = sysctl("kern.corefile");
        assert_eq!(
            Path::new(&pattern),
            dir.join("core.%P"),
            "ENVCLOAK_TEST_CORE_DIR is set, but kern.corefile is {pattern:?}"
        );
    }
    Some(dir)
}

/// Core files a crash of `pid` could have left: `core` or `core.*` in
/// `cwd`, `/cores/core.<pid>` (macOS), and `core.<pid>` in `dumps`.
pub fn core_files(cwd: &Path, dumps: Option<&Path>, pid: i32) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(cwd)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| {
                    let name = e.file_name();
                    let name = name.to_string_lossy();
                    name == "core" || name.starts_with("core.")
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    let mut elsewhere = vec![PathBuf::from(format!("/cores/core.{pid}"))];
    elsewhere.extend(dumps.map(|d| d.join(format!("core.{pid}"))));
    found.extend(elsewhere.into_iter().filter(|p| p.exists()));
    found
}

/// Signal number and core-dump flag of an exit status.
pub trait StatusExt {
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

/// Entitlements that let a debugger attach to the process (and, on macOS,
/// let it dump core).
#[cfg(target_os = "macos")]
const GET_TASK_ALLOW: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>\n";

/// Copies `program` to `dir/name` and signs the copy ad hoc, with the
/// hardened runtime if `runtime`, and with `get-task-allow` if
/// `debuggable`. Checks with `codesign --display` that the signature says
/// exactly that, and returns the copy.
///
/// # Panics
/// When copying or signing fails, or the signature says otherwise.
#[cfg(target_os = "macos")]
pub fn signed_copy(
    program: &Path,
    dir: &Path,
    name: &str,
    runtime: bool,
    debuggable: bool,
) -> PathBuf {
    let copy = dir.join(name);
    if let Err(e) = std::fs::copy(program, &copy) {
        panic!("copying {}: {e}", program.display());
    }
    let mut cmd = Command::new("codesign");
    cmd.args(["--force", "--sign", "-"]);
    if runtime {
        cmd.args(["--options", "runtime"]);
    }
    if debuggable {
        let plist = dir.join(format!("{name}.entitlements"));
        if let Err(e) = std::fs::write(&plist, GET_TASK_ALLOW) {
            panic!("writing entitlements: {e}");
        }
        cmd.arg("--entitlements").arg(plist);
    }
    let signed = cmd
        .arg(&copy)
        .output()
        .unwrap_or_else(|e| panic!("codesign: {e}"));
    assert!(signed.status.success(), "codesign failed: {signed:?}");
    let shown = Command::new("codesign")
        .args(["--display", "--verbose=2", "--entitlements", "-"])
        .arg(&copy)
        .output()
        .unwrap_or_else(|e| panic!("codesign --display: {e}"));
    assert!(shown.status.success(), "{shown:?}");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&shown.stdout),
        String::from_utf8_lossy(&shown.stderr)
    );
    let runtime_flag = text
        .lines()
        .filter(|l| l.starts_with("CodeDirectory "))
        .any(|l| {
            l.split_whitespace()
                .find_map(|w| w.strip_prefix("flags="))
                .is_some_and(|f| f.contains("runtime"))
        });
    assert_eq!(runtime_flag, runtime, "{text}");
    assert_eq!(
        text.contains("com.apple.security.get-task-allow"),
        debuggable,
        "{text}"
    );
    copy
}
